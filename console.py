from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.live import Live
from rich.layout import Layout
from rich import box

from ai_explainer import AIProviderConfig, get_provider
from detector import analyze_email
from ioc.extractor import extract_iocs
from intel import get_provider as get_intel_provider
from intel.osint import get_osint_provider
from parser.email_parser import parse_email
from reporter import generate_case_directory, generate_mitre_navigator_layer, generate_report
from rules.rule_generator import RuleGenerator
from whitelist import WhitelistConfig, MatcherMode, set_config
from memory.database import get_db, ThreatDNA as DBThreatDNA

logger = logging.getLogger(__name__)


def _confidence(score: int) -> str:
    if score >= 10:
        return "HIGH"
    if score >= 5:
        return "MEDIUM"
    return "LOW"


def _verdict_style(verdict: str) -> str:
    if verdict == "PHISHING":
        return "bold red"
    if verdict == "SUSPICIOUS":
        return "bold yellow"
    return "bold green"


def _verdict_color(verdict: str) -> str:
    if verdict == "PHISHING":
        return "red"
    if verdict == "SUSPICIOUS":
        return "yellow"
    return "green"


class Case:
    def __init__(self, file_path: Path, case_dir: Path):
        self.file_path = file_path
        self.case_dir = case_dir
        self.email_data = None
        self.iocs: Dict[str, Any] = {}
        self.analysis: Dict[str, Any] = {}
        self.intel_results: Optional[Dict[str, Any]] = None
        self.loaded = False
        self.analyzed = False


class PhishXConsole:
    def __init__(self, output_dir: Path = Path("reports"), ai_config: Optional[AIProviderConfig] = None, sound: bool = False, db_path: Optional[Path] = None):
        self.console = Console()
        self.output_dir = output_dir
        self.ai_config = ai_config or AIProviderConfig()
        self.sound = sound
        self.db = get_db(db_path)
        self.cases: Dict[int, Case] = {}
        self.active_case_id: Optional[int] = None
        self.case_counter = 0
        self.history: List[str] = []
        self.running = False

    def _beep(self) -> None:
        if not self.sound:
            return
        try:
            if sys.platform == "darwin":
                import subprocess
                subprocess.run(["afplay", "/System/Library/Sounds/Glass.aiff"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif sys.platform == "linux":
                import subprocess
                subprocess.run(["paplay", "/usr/share/sounds/freedesktop/stereo/bell.ogg"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                sys.stdout.write("\a")
                sys.stdout.flush()
        except Exception:
            pass

    def _banner(self) -> None:
        banner_text = (
            "[bold cyan]██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██╗  ██╗\n"
            "██████╔╝███████║██║███████╗███████║ ╚███╔╝\n"
            "██╔═══╝ ██╔══██║██║╚════██║██╔══██║ ██╔██╗\n"
            "██║     ██║  ██║██║███████║██║  ██║██╔╝ ██╗\n"
            "╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝[/bold cyan]\n"
            "[bold white]AI Phishing Investigation Framework[/bold white]"
        )
        banner = Panel(
            banner_text,
            title="[bold white]PHISHX[/bold white]",
            subtitle="[dim]v2.0 | Interactive SOC Console[/dim]",
            border_style="cyan",
            padding=(0, 2),
        )
        self.console.print(banner)
        self.console.print()

    def _prompt(self) -> str:
        if self.active_case_id is not None:
            case = self.cases[self.active_case_id]
            name = case.file_path.name
            if case.analyzed and case.analysis:
                verdict = case.analysis.get("verdict", "")
                color = _verdict_color(verdict)
                return f"[bold {color}]phishx([yellow]{name}[/yellow])[/bold {color}] > "
            return f"[bold cyan]phishx([yellow]{name}[/yellow])[/bold cyan] > "
        return "[bold cyan]phishx[/bold cyan] > "

    def _print_status(self, message: str) -> None:
        self.console.print(f"[bold cyan]⚡ {message}[/bold cyan]")

    def _threat_meter(self, score: int, max_score: int = 20) -> str:
        pct = min(score / max_score, 1.0)
        filled = int(pct * 20)
        bar = "█" * filled + "░" * (20 - filled)
        if score >= 10:
            color = "bold red"
        elif score >= 5:
            color = "bold yellow"
        else:
            color = "bold green"
        return f"[{color}]{bar}[/{color}] {score}/{max_score}"

    def _live_progress_analyze(self, case: Case) -> None:
        steps = [
            "Parsing email",
            "Extracting IoCs",
            "Authentication checks",
            "Running detection rules",
            "Threat intelligence",
            "Report generation",
        ]
        with Live(console=self.console, refresh_per_second=10, transient=True) as live:
            for idx, step in enumerate(steps, 1):
                live.update(f"[bold white][{idx}/6][/bold white] {step}... [green]✓[/green]")
                time.sleep(0.4)

    def _load_case(self, file_path: Path) -> Case:
        self.case_counter += 1
        case_dir = generate_case_directory(file_path, {})
        case = Case(file_path=file_path, case_dir=case_dir)
        self.cases[self.case_counter] = case
        self.active_case_id = self.case_counter
        return case

    def cmd_load(self, args: str) -> bool:
        parts = args.strip().split()
        if not parts or not parts[0]:
            self.console.print("[red]Usage: load <path-to-.eml>[/red]")
            return True
        target = Path(parts[0])
        if not target.exists():
            self.console.print(f"[red]File not found: {target}[/red]")
            return True
        if target.is_dir():
            eml_files = sorted(target.rglob("*.eml"))
            if not eml_files:
                self.console.print(f"[red]No .eml files found in {target}[/red]")
                return True
            loaded = 0
            for eml in eml_files:
                self._load_case(eml)
                loaded += 1
            self.console.print(f"[green]✓[/green] Loaded {loaded} email(s) from [cyan]{target}[/cyan]")
            return True
        case = self._load_case(target)
        self.console.print(f"[green]✓[/green] Loaded [cyan]{target.name}[/cyan]")
        return True

    def cmd_analyze(self, _args: str) -> bool:
        if self.active_case_id is None:
            self.console.print("[red]No case loaded. Use 'load <file>' first.[/red]")
            return True
        case = self.cases[self.active_case_id]
        try:
            self._print_status("Parsing email")
            case.email_data = parse_email(case.file_path)

            headers_str = "\n".join(f"{k}: {v}" for k, v in case.email_data.headers.items())
            combined_text = headers_str + "\n" + case.email_data.body_text + "\n" + case.email_data.body_html
            for url in case.email_data.urls_from_html:
                combined_text += "\n" + url

            case.iocs = extract_iocs(combined_text)

            extracted_data = {
                "headers": headers_str,
                "urls": case.iocs["urls"],
                "domains": case.iocs["domains"],
                "ips": case.iocs["ips"],
                "emails": case.iocs["emails"],
                "body_text": case.email_data.body_text,
                "body_html": case.email_data.body_html,
                "forms": case.email_data.forms,
            }

            self._live_progress_analyze(case)

            case.analysis = analyze_email(extracted_data)

            generate_report(case.email_data.__dict__, case.iocs, case.analysis, email_path=case.file_path, case_dir=case.case_dir)
            mitre_path = case.case_dir / f"{case.case_dir.name}_mitre_layer.json"
            generate_mitre_navigator_layer(case.analysis, case.case_dir.name, mitre_path)

            case.loaded = True
            case.analyzed = True
            self._persist_case(case)
            self._print_summary(case)
            self._beep()
        except Exception as exc:
            self.console.print(f"[red]✗ Analysis failed:[/red] {exc}")
            logger.error("Analysis failed: %s", exc)
        return True

    def _print_summary(self, case: Case) -> None:
        if not case.analysis:
            self.console.print("[yellow]No analysis yet. Run 'analyze' first.[/yellow]")
            return
        summary = Table(show_header=False, box=None, padding=(0, 2))
        summary.add_column("Key", style="bold cyan", no_wrap=True)
        summary.add_column("Value")
        summary.add_row("Case ID", case.case_dir.name)
        summary.add_row("Email", case.file_path.name)
        summary.add_row("Verdict", Text(case.analysis["verdict"], style=_verdict_style(case.analysis["verdict"])))
        summary.add_row("Score", self._threat_meter(case.analysis["score"]))
        summary.add_row("Confidence", _confidence(case.analysis["score"]))
        summary.add_row("URLs", str(len(case.iocs.get("urls", []))))
        summary.add_row("Domains", str(len(case.iocs.get("domains", []))))
        summary.add_row("IPs", str(len(case.iocs.get("ips", []))))
        summary.add_row("Emails", str(len(case.iocs.get("emails", []))))
        self.console.print(Panel(summary, title="[bold]Investigation Summary[/bold]", border_style="blue", padding=(1, 2)))
        if case.analysis.get("reasons"):
            reasons = Table(show_header=False, box=None, padding=(0, 2))
            reasons.add_column("•", style="bold red", no_wrap=True)
            for reason in case.analysis["reasons"]:
                reasons.add_row(reason)
            self.console.print(Panel(reasons, title="[bold red]Detection Reasons[/bold red]", border_style="red", padding=(1, 2)))

    def cmd_summary(self, _args: str) -> bool:
        if self.active_case_id is None:
            self.console.print("[red]No case loaded.[/red]")
            return True
        self._print_summary(self.cases[self.active_case_id])
        return True

    def _drill_table(self, title: str, items: List[tuple], style: str = "cyan") -> None:
        table = Table(title=title, show_header=True, header_style="bold magenta")
        table.add_column("#", style="dim", width=4)
        table.add_column("Value", style=style)
        for idx, value, extra in items:
            row = [str(idx), value]
            if extra:
                table.add_column("Details", style="dim")
                table.add_row(str(idx), value, extra)
            else:
                table.add_row(str(idx), value)
        self.console.print(table)

    def cmd_urls(self, _args: str) -> bool:
        if self.active_case_id is None:
            self.console.print("[red]No case loaded.[/red]")
            return True
        case = self.cases[self.active_case_id]
        urls = case.iocs.get("urls", [])
        if not urls:
            self.console.print("[yellow]No URLs found.[/yellow]")
            return True
        items = [(i + 1, url, None) for i, url in enumerate(urls)]
        self._drill_table("Extracted URLs", items, style="cyan")
        return True

    def cmd_domains(self, _args: str) -> bool:
        if self.active_case_id is None:
            self.console.print("[red]No case loaded.[/red]")
            return True
        case = self.cases[self.active_case_id]
        domains = case.iocs.get("domains", [])
        if not domains:
            self.console.print("[yellow]No domains found.[/yellow]")
            return True
        items = [(i + 1, d, None) for i, d in enumerate(domains)]
        self._drill_table("Extracted Domains", items, style="cyan")
        return True

    def cmd_ips(self, _args: str) -> bool:
        if self.active_case_id is None:
            self.console.print("[red]No case loaded.[/red]")
            return True
        case = self.cases[self.active_case_id]
        ips = case.iocs.get("ips", [])
        if not ips:
            self.console.print("[yellow]No IPs found.[/yellow]")
            return True
        items = [(i + 1, ip, None) for i, ip in enumerate(ips)]
        self._drill_table("Extracted IPs", items, style="cyan")
        return True

    def cmd_headers(self, _args: str) -> bool:
        if self.active_case_id is None:
            self.console.print("[red]No case loaded.[/red]")
            return True
        case = self.cases[self.active_case_id]
        if case.email_data is None:
            self.console.print("[yellow]Email not parsed. Run 'analyze' first.[/yellow]")
            return True
        headers_str = "\n".join(f"{k}: {v}" for k, v in case.email_data.headers.items())
        self.console.print(Panel(headers_str, title="[bold]Email Headers[/bold]", border_style="blue", padding=(1, 2)))
        return True

    def cmd_forms(self, _args: str) -> bool:
        if self.active_case_id is None:
            self.console.print("[red]No case loaded.[/red]")
            return True
        case = self.cases[self.active_case_id]
        forms = case.email_data.forms if case.email_data else []
        if not forms:
            self.console.print("[yellow]No forms found.[/yellow]")
            return True
        for idx, form in enumerate(forms, 1):
            self.console.print(f"[bold]#{idx}[/bold] action=[cyan]{form.get('action')}[/cyan] method=[yellow]{form.get('method')}[/yellow]")
            inputs = form.get("inputs", [])
            if inputs:
                self.console.print(f"   inputs: {', '.join(inputs)}")
        return True

    def cmd_attachments(self, _args: str) -> bool:
        if self.active_case_id is None:
            self.console.print("[red]No case loaded.[/red]")
            return True
        case = self.cases[self.active_case_id]
        attachments = case.email_data.attachments if case.email_data else []
        if not attachments:
            self.console.print("[yellow]No attachments found.[/yellow]")
            return True
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("#")
        table.add_column("Filename")
        table.add_column("Size")
        for idx, att in enumerate(attachments, 1):
            table.add_row(str(idx), att.get("filename", "?"), att.get("size", "?"))
        self.console.print(table)
        return True

    def cmd_mitre(self, _args: str) -> bool:
        if self.active_case_id is None:
            self.console.print("[red]No case loaded.[/red]")
            return True
        case = self.cases[self.active_case_id]
        if not case.analyzed:
            self.console.print("[yellow]Case not analyzed yet.[/yellow]")
            return True
        mitre_path = case.case_dir / f"{case.case_dir.name}_mitre_layer.json"
        if not mitre_path.exists():
            self.console.print("[yellow]MITRE layer not generated.[/yellow]")
            return True
        try:
            data = json.loads(mitre_path.read_text(encoding="utf-8"))
            techniques = data.get("techniques", [])
            if not techniques:
                self.console.print("[yellow]No MITRE techniques mapped.[/yellow]")
                return True
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Technique ID")
            table.add_column("Name")
            table.add_column("Tactic")
            for t in techniques:
                tid = t.get("techniqueID", "?")
                name = t.get("name", "?")
                tactic = t.get("tactic", "?")
                table.add_row(tid, name, tactic)
            self.console.print(table)
        except Exception as exc:
            self.console.print(f"[red]Failed to read MITRE layer:[/red] {exc}")
        return True

    def cmd_intel(self, args: str) -> bool:
        if self.active_case_id is None:
            self.console.print("[red]No case loaded.[/red]")
            return True
        case = self.cases[self.active_case_id]
        if not case.iocs:
            self.console.print("[yellow]No IoCs. Run 'analyze' first.[/yellow]")
            return True
        provider_name = args.strip().lower() or "urlhaus"
        try:
            provider = get_intel_provider(provider_name)
        except ValueError as exc:
            self.console.print(f"[red]{exc}[/red]")
            return True
        self.console.print(f"[cyan]Enriching IoCs with [bold]{provider_name}[/bold]...[/cyan]")
        try:
            enriched = self._enrich_with_progress(case.iocs, provider)
            case.intel_results = enriched
            self._print_intel_summary(enriched)
        except Exception as exc:
            self.console.print(f"[red]Threat intel failed:[/red] {exc}")
        return True

    def _enrich_with_progress(self, iocs: Dict[str, Any], provider: Any) -> Dict[str, Any]:
        enriched: Dict[str, Any] = {"urls": [], "domains": [], "ips": []}
        urls = iocs.get("urls", [])
        domains = iocs.get("domains", [])
        ips = iocs.get("ips", [])
        total = len(urls) + len(domains) + len(ips)
        count = 0
        for url in urls:
            count += 1
            self.console.print(f"   [dim][{count}/{total}] Checking URL:[/dim] [cyan]{url}[/cyan]")
            enriched["urls"].append(provider.check_url(url))
        for domain in domains:
            count += 1
            self.console.print(f"   [dim][{count}/{total}] Checking domain:[/dim] [cyan]{domain}[/cyan]")
            enriched["domains"].append(provider.check_domain(domain))
        for ip in ips:
            count += 1
            self.console.print(f"   [dim][{count}/{total}] Checking IP:[/dim] [cyan]{ip}[/cyan]")
            enriched["ips"].append(provider.check_ip(ip))
        return enriched

    def _print_intel_summary(self, enriched: Dict[str, Any]) -> None:
        for section, key, color in [("URLs", "urls", "cyan"), ("Domains", "domains", "cyan"), ("IPs", "ips", "cyan")]:
            items = enriched.get(key, [])
            if not items:
                continue
            table = Table(title=section, show_header=True, header_style="bold magenta")
            table.add_column("Query", style=color)
            table.add_column("Status / Result")
            for item in items:
                query = item.get("query", "?")
                if "error" in item:
                    status = f"[red]Error: {item['error']}[/red]"
                elif item.get("provider") == "urlhaus":
                    status = item.get("status", "unknown")
                    threat = item.get("threat", "unknown")
                    tags = ", ".join(item.get("tags", []))
                    status = f"[yellow]{threat}[/yellow] | {status}"
                    if tags:
                        status += f" | {tags}"
                elif item.get("provider") == "virustotal":
                    mal = item.get("malicious", 0)
                    susp = item.get("suspicious", 0)
                    status = f"[red]{mal}[/red] malicious, [yellow]{susp}[/yellow] suspicious"
                else:
                    status = str(item)
                table.add_row(query, status)
            self.console.print(table)

    def cmd_export(self, args: str) -> bool:
        if self.active_case_id is None:
            self.console.print("[red]No case loaded.[/red]")
            return True
        case = self.cases[self.active_case_id]
        fmt = args.strip().lower() or "text"
        base = case.case_dir / case.case_dir.name
        try:
            if fmt == "text":
                path = base.with_suffix(".txt")
            elif fmt == "json":
                path = base.with_suffix(".json")
            elif fmt == "mitre":
                path = base.parent / f"{base.name}_mitre_layer.json"
            else:
                self.console.print(f"[red]Unknown format: {fmt}. Use text|json|mitre[/red]")
                return True
            if not path.exists():
                self.console.print(f"[yellow]File not generated: {path}[/yellow]")
            else:
                self.console.print(f"[green]✓[/green] Exported: [cyan]{path}[/cyan]")
        except Exception as exc:
            self.console.print(f"[red]Export failed:[/red] {exc}")
        return True

    def cmd_history(self, _args: str) -> bool:
        if not self.history:
            self.console.print("[yellow]No history yet.[/yellow]")
            return True
        table = Table(show_header=False, box=None)
        table.add_column("#", style="dim", width=4)
        table.add_column("Command", style="cyan")
        for idx, cmd in enumerate(self.history, 1):
            table.add_row(str(idx), cmd)
        self.console.print(table)
        return True

    def cmd_cases(self, _args: str) -> bool:
        if not self.cases:
            self.console.print("[yellow]No cases loaded.[/yellow]")
            return True
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Case", style="dim")
        table.add_column("Email")
        table.add_column("Verdict")
        table.add_column("Score")
        for cid, case in self.cases.items():
            verdict = case.analysis.get("verdict", "-") if case.analyzed else "-"
            score = str(case.analysis.get("score", "-")) if case.analyzed else "-"
            marker = "*" if self.active_case_id == cid else " "
            table.add_row(f"{marker}{cid}", case.file_path.name, Text(verdict, style=_verdict_style(verdict) if case.analyzed else "white"), score)
        self.console.print(table)
        return True

    def cmd_use(self, args: str) -> bool:
        parts = args.strip().split()
        if not parts:
            self.console.print("[red]Usage: use <case-number>[/red]")
            return True
        try:
            cid = int(parts[0])
        except ValueError:
            self.console.print("[red]Invalid case number.[/red]")
            return True
        if cid not in self.cases:
            self.console.print(f"[red]Case {cid} not found.[/red]")
            return True
        self.active_case_id = cid
        case = self.cases[cid]
        self.console.print(f"[green]✓[/green] Switched to case [cyan]{cid}[/cyan]: [yellow]{case.file_path.name}[/yellow]")
        return True

    def _persist_case(self, case: Case) -> None:
        if not case.analyzed or not case.analysis:
            return
        case_id = case.case_dir.name
        self.db.save_case(
            case_id=case_id,
            email_path=str(case.file_path),
            case_dir=str(case.case_dir),
            verdict=case.analysis.get("verdict", "UNKNOWN"),
            score=case.analysis.get("score", 0),
            confidence=_confidence(case.analysis.get("score", 0)),
        )
        self.db.save_iocs(case_id, case.iocs)
        from memory.dna import compute_threat_dna
        dna = compute_threat_dna(case.email_data, case.iocs, case.analysis)
        self.db.save_threat_dna(case_id, dna)

    def cmd_dna(self, _args: str) -> bool:
        if self.active_case_id is None:
            self.console.print("[red]No case loaded.[/red]")
            return True
        case = self.cases[self.active_case_id]
        if not case.analyzed:
            self.console.print("[yellow]Case not analyzed yet.[/yellow]")
            return True
        case_id = case.case_dir.name
        dna = self.db.get_threat_dna(case_id)
        if not dna:
            self.console.print("[yellow]No threat DNA computed yet. Run 'analyze' first.[/yellow]")
            return True
        table = Table(title="Threat DNA Fingerprint", show_header=True, header_style="bold magenta")
        table.add_column("Attribute", style="cyan")
        table.add_column("Value", style="white")
        fields = [
            ("HTML Hash", dna.get("html_hash", "")),
            ("CSS Hash", dna.get("css_hash", "")),
            ("Subject Pattern", dna.get("subject_pattern", "")),
            ("Sender Domain", dna.get("sender_domain", "")),
            ("Registrar", dna.get("registrar", "")),
            ("Hosting Provider", dna.get("hosting_provider", "")),
            ("Language", dna.get("language", "")),
            ("Timezone", dna.get("timezone", "")),
            ("Form Action Domain", dna.get("form_action_domain", "")),
            ("URL Patterns", ", ".join(json.loads(dna.get("url_patterns", "[]")) or [])),
            ("Attachment Types", ", ".join(json.loads(dna.get("attachment_types", "[]")) or [])),
        ]
        for key, value in fields:
            table.add_row(key, value or "-")
        self.console.print(table)
        similar = self.db.find_similar_dna(json.loads(dna.get("dna_vector", "{}") or "{}"))
        if similar:
            self.console.print()
            self.console.print("[bold cyan]Similar Cases:[/bold cyan]")
            sim_table = Table(show_header=True, header_style="bold magenta")
            sim_table.add_column("Case ID", style="dim")
            sim_table.add_column("Similarity")
            for s in similar:
                sim_table.add_row(s["case_id"], f"{int(s['similarity']*100)}%")
            self.console.print(sim_table)
        return True

    def cmd_campaign(self, _args: str) -> bool:
        if self.active_case_id is None:
            self.console.print("[red]No case loaded.[/red]")
            return True
        case = self.cases[self.active_case_id]
        if not case.analyzed:
            self.console.print("[yellow]Case not analyzed yet.[/yellow]")
            return True
        case_id = case.case_dir.name
        campaigns = self.db.get_campaigns_for_case(case_id)
        if not campaigns:
            self.console.print("[yellow]No campaigns linked yet. Cases are linked when similarity is detected.[/yellow]")
            related = self.db.get_related_cases(case_id)
            if related:
                self.console.print()
                self.console.print(f"[cyan]Related cases detected:[/cyan] {len(related)}")
                for r in related[:5]:
                    self.console.print(f"  - {r.get('case_id', '?')} (similarity: {r.get('similarity', 0)})")
            return True
        table = Table(title="Linked Campaigns", show_header=True, header_style="bold magenta")
        table.add_column("Campaign ID", style="dim")
        table.add_column("Name")
        table.add_column("Confidence")
        table.add_column("Cases")
        for camp in campaigns:
            try:
                case_list = json.loads(camp.get("case_count", "[]"))
            except Exception:
                case_list = []
            table.add_row(
                camp["campaign_id"],
                camp.get("name", "?"),
                camp.get("confidence", "?"),
                str(len(case_list)),
            )
        self.console.print(table)
        return True

    def cmd_rules(self, _args: str) -> bool:
        if self.active_case_id is None:
            self.console.print("[red]No case loaded.[/red]")
            return True
        case = self.cases[self.active_case_id]
        if not case.analyzed:
            self.console.print("[yellow]Case not analyzed yet.[/yellow]")
            return True
        generator = RuleGenerator(case.analysis, case.iocs, case.email_data)
        all_rules = generator.generate_all()
        fmt = _args.strip().lower() or "all"
        if fmt == "sigma":
            self.console.print(Panel(all_rules["sigma"], title="[bold]Sigma Rule[/bold]", border_style="green", padding=(1, 2)))
        elif fmt == "yara":
            self.console.print(Panel(all_rules["yara"], title="[bold]YARA Rule[/bold]", border_style="yellow", padding=(1, 2)))
        elif fmt == "suricata":
            self.console.print(Panel(all_rules["suricata"], title="[bold]Suricata Rules[/bold]", border_style="blue", padding=(1, 2)))
        else:
            for name, content in all_rules.items():
                if content.strip():
                    self.console.print(Panel(content, title=f"[bold]{name.upper()} Rule[/bold]", padding=(1, 2)))
                    self.console.print()
        return True

    def cmd_note(self, args: str) -> bool:
        if self.active_case_id is None:
            self.console.print("[red]No case loaded.[/red]")
            return True
        case = self.cases[self.active_case_id]
        note = args.strip()
        if not note:
            note = Prompt.ask("Enter analyst note")
        case_id = case.case_dir.name
        note_id = self.db.add_analyst_note(case_id, note)
        self.console.print(f"[green]✓[/green] Note added (ID: {note_id})")
        return True

    def cmd_relationships(self, _args: str) -> bool:
        if self.active_case_id is None:
            self.console.print("[red]No case loaded.[/red]")
            return True
        case = self.cases[self.active_case_id]
        if not case.analyzed:
            self.console.print("[yellow]Case not analyzed yet.[/yellow]")
            return True
        case_id = case.case_dir.name
        related = self.db.get_related_cases(case_id)
        if not related:
            self.console.print("[yellow]No related cases found in memory.[/yellow]")
            return True
        table = Table(title="Related Cases", show_header=True, header_style="bold magenta")
        table.add_column("Case ID", style="dim")
        table.add_column("Similarity")
        table.add_column("Reason")
        for r in related:
            table.add_row(
                r.get("case_id", "?"),
                f"{int((r.get('similarity', 0) or 0) * 100)}%",
                r.get("reason", ""),
            )
        self.console.print(table)
        return True

    def cmd_intel(self, args: str) -> bool:
        if self.active_case_id is None:
            self.console.print("[red]No case loaded.[/red]")
            return True
        case = self.cases[self.active_case_id]
        if not case.iocs:
            self.console.print("[yellow]No IoCs. Run 'analyze' first.[/yellow]")
            return True
        parts = args.strip().split(maxsplit=1)
        provider_name = parts[0].lower() if parts else "urlhaus"
        provider_args = parts[1] if len(parts) > 1 else ""
        if provider_name == "history":
            return self._intel_history(provider_args)
        if provider_name == "osint":
            return self._intel_osint(provider_args)
        try:
            provider = get_intel_provider(provider_name)
        except ValueError as exc:
            self.console.print(f"[red]{exc}[/red]")
            return True
        self.console.print(f"[cyan]Enriching IoCs with [bold]{provider_name}[/bold]...[/cyan]")
        try:
            enriched = self._enrich_with_progress(case.iocs, provider)
            case.intel_results = enriched
            self._print_intel_summary(enriched)
        except Exception as exc:
            self.console.print(f"[red]Threat intel failed:[/red] {exc}")
        return True

    def _intel_history(self, ioc_value: str) -> bool:
        if not ioc_value:
            self.console.print("[red]Usage: intel history <ioc-value>[/red]")
            return True
        history = self.db.get_ioc_history(ioc_value)
        if not history:
            self.console.print(f"[yellow]No history found for: {ioc_value}[/yellow]")
            return True
        table = Table(title=f"IOC History: {ioc_value}", show_header=True, header_style="bold magenta")
        table.add_column("Case ID", style="dim")
        table.add_column("Type")
        table.add_column("First Seen")
        table.add_column("Last Seen")
        table.add_column("Count")
        for h in history:
            table.add_row(
                h.get("case_id", "?"),
                h.get("ioc_type", "?"),
                h.get("first_seen", "?"),
                h.get("last_seen", "?"),
                str(h.get("seen_count", 0)),
            )
        self.console.print(table)
        return True

    def _intel_osint(self, provider_name: str) -> bool:
        if not provider_name:
            self.console.print("[red]Usage: intel osint <provider>[/red]\nProviders: abuseipdb, cisa-kev, rdap, doh, phishtank, alienvault-otx[/red]")
            return True
        if self.active_case_id is None:
            self.console.print("[red]No case loaded.[/red]")
            return True
        case = self.cases[self.active_case_id]
        try:
            provider = get_osint_provider(provider_name)
        except ValueError as exc:
            self.console.print(f"[red]{exc}[/red]")
            return True
        self.console.print(f"[cyan]Querying [bold]{provider_name}[/bold] OSINT...[/cyan]")
        items = []
        if provider_name in ("abuseipdb", "rdap", "cisa-kev"):
            items = [(ip, "ip") for ip in case.iocs.get("ips", [])]
        if provider_name in ("doh", "phishtank", "alienvault-otx"):
            items.extend([(d, "domain") for d in case.iocs.get("domains", [])])
            items.extend([(u, "url") for u in case.iocs.get("urls", [])])
        if not items:
            self.console.print("[yellow]No compatible IOCs for this provider.[/yellow]")
            return True
        table = Table(title=f"OSINT Results ({provider_name})", show_header=True, header_style="bold magenta")
        table.add_column("Query", style="cyan")
        table.add_column("Type")
        table.add_column("Result")
        for value, ioc_type in items:
            if ioc_type == "ip":
                result = provider.check_ip(value)
            elif ioc_type == "domain":
                result = provider.check_domain(value)
            else:
                result = provider.check_url(value)
            if "error" in result:
                result_str = f"[red]Error: {result['error']}[/red]"
            else:
                parts = []
                for k, v in result.items():
                    if k in ("provider", "query"):
                        continue
                    if v:
                        parts.append(f"{k}={v}")
                result_str = " | ".join(parts) if parts else "[green]Checked[/green]"
            table.add_row(value, ioc_type, result_str)
        self.console.print(table)
        return True
        self.console.clear()
        self._banner()
        return True

    def cmd_help(self, _args: str) -> bool:
        table = Table(title="Available Commands", show_header=True, header_style="bold magenta")
        table.add_column("Command", style="cyan")
        table.add_column("Description", style="white")
        commands = [
            ("load <path>", "Load .eml file or directory"),
            ("analyze", "Run full investigation on loaded case"),
            ("summary", "Show investigation summary"),
            ("urls", "List extracted URLs"),
            ("domains", "List extracted domains"),
            ("ips", "List extracted IPs"),
            ("headers", "Show email headers"),
            ("forms", "Show HTML forms"),
            ("attachments", "Show attachments"),
            ("mitre", "Show MITRE ATT&CK mapping"),
            ("intel [provider]", "Enrich IoCs (urlhaus|virustotal)"),
            ("export [format]", "Export report (text|json|mitre)"),
            ("cases", "List loaded cases"),
            ("use <id>", "Switch active case"),
            ("history", "Show command history"),
            ("clear", "Clear screen"),
            ("ask <question>", "Ask AI about the case"),
            ("dna", "Show threat DNA fingerprint"),
            ("campaign", "Detect related campaigns"),
            ("rules", "Generate detection rules (sigma/yara/suricata)"),
            ("note <text>", "Add analyst note to case"),
            ("relationships", "Show related cases"),
            ("intel history <ioc>", "Look up IOC history in local DB"),
            ("intel osint <provider>", "Check IOC via free OSINT source"),
            ("exit / quit", "Exit console"),
        ]
        for cmd, desc in commands:
            table.add_row(cmd, desc)
        self.console.print(table)
        return True

    def cmd_ask(self, args: str) -> bool:
        if self.active_case_id is None:
            self.console.print("[red]No case loaded.[/red]")
            return True
        case = self.cases[self.active_case_id]
        if not case.analyzed:
            self.console.print("[yellow]Case not analyzed yet. Run 'analyze' first.[/yellow]")
            return True
        question = args.strip()
        if not question:
            question = Prompt.ask("Enter your question")
        self.console.print("[cyan]Thinking...[/cyan]")
        try:
            provider = get_provider(self.ai_config)
            indicators = "\n".join(f"- {r}" for r in case.analysis.get("reasons", []))
            headers_text = (
                "\n".join(f"{k}: {v}" for k, v in case.email_data.headers.items())
                if case.email_data
                else ""
            )
            email_text = (
                headers_text
                + " "
                + (case.email_data.body_text if case.email_data else "")
                + " "
                + (case.email_data.body_html if case.email_data else "")
            )[:1500]
            context = f"Question: {question}\n\nEmail indicators:\n{indicators}\n\nEmail excerpt: {email_text}"
            prompt = (
                "You are a cybersecurity analyst assisting a SOC team. "
                "Answer the analyst's question concisely and accurately based on the provided email analysis results.\n\n"
                f"{context}\n\nAnswer:"
            )
            if self.ai_config.provider == "ollama":
                answer = self._ask_ollama_stream(prompt)
            elif self.ai_config.provider == "openai":
                answer = self._ask_openai(prompt)
            elif self.ai_config.provider == "anthropic":
                answer = self._ask_anthropic(prompt)
            else:
                answer = "Unsupported AI provider."
            self.console.print(Panel(answer, title="[bold]AI Response[/bold]", border_style="blue", padding=(1, 2)))
        except Exception as exc:
            self.console.print(f"[red]AI request failed:[/red] {exc}")
        return True

    def _ask_ollama_stream(self, prompt: str) -> str:
        url = f"{self.ai_config.base_url}/api/generate"
        payload = {
            "model": self.ai_config.model,
            "prompt": prompt,
            "stream": True,
            "options": {"num_predict": 300, "temperature": 0.3},
        }
        import requests
        resp = requests.post(url, json=payload, timeout=120, stream=True)
        resp.raise_for_status()
        full = []
        for line in resp.iter_lines(decode_unicode=True):
            if line:
                data = json.loads(line)
                if "response" in data:
                    chunk = data["response"]
                    full.append(chunk)
                    self.console.print(chunk, end="")
        self.console.print()
        return "".join(full)

    def _ask_openai(self, prompt: str) -> str:
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise ImportError("openai package required. Install with: pip install ai-phishing-investigator[ai]") from exc
        client = OpenAI(api_key=self.ai_config.api_key)
        response = client.chat.completions.create(
            model=self.ai_config.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=300,
        )
        return response.choices[0].message.content or "No response."

    def _ask_anthropic(self, prompt: str) -> str:
        try:
            from anthropic import Anthropic
        except ImportError as exc:
            raise ImportError("anthropic package required. Install with: pip install ai-phishing-investigator[ai]") from exc
        client = Anthropic(api_key=self.ai_config.api_key)
        message = client.messages.create(
            model=self.ai_config.model,
            max_tokens=300,
            temperature=0.3,
            messages=[{"role": "user", "content": prompt}],
        )
        return message.content[0].text

    def run(self) -> None:
        self.running = True
        self._banner()
        self.console.print("[dim]Type 'help' for commands, 'load <file>' to begin.[/dim]\n")
        while self.running:
            try:
                raw = Prompt.ask(self._prompt(), console=self.console)
                if raw is None:
                    continue
                raw = raw.strip()
                if not raw:
                    continue
                self.history.append(raw)
                parts = raw.split(maxsplit=1)
                cmd = parts[0].lower()
                args = parts[1] if len(parts) > 1 else ""
                if cmd in ("exit", "quit"):
                    self.console.print("[yellow]Goodbye.[/yellow]")
                    self.running = False
                    continue
                handler = getattr(self, f"cmd_{cmd}", None)
                if handler is None:
                    self.console.print(f"[red]Unknown command: {cmd}. Type 'help' for options.[/red]")
                    continue
                handler(args)
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Interrupted. Type 'exit' to quit.[/yellow]")
            except Exception as exc:
                logger.error("Console error: %s", exc)
                self.console.print(f"[red]Error:[/red] {exc}")


def start_console(output_dir: Path = Path("reports"), ai_config: Optional[AIProviderConfig] = None, sound: bool = False, db_path: Optional[Path] = None) -> None:
    console = PhishXConsole(output_dir=output_dir, ai_config=ai_config, sound=sound, db_path=db_path)
    console.run()
