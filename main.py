from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.logging import RichHandler

console = Console()

logger = logging.getLogger(__name__)

from ai_explainer import AIProviderConfig, ai_explain
from detector import analyze_email
from ioc.extractor import extract_iocs
from parser.email_parser import EmailData, parse_email
from reporter import generate_case_directory, generate_mitre_navigator_layer, generate_report
from whitelist import WhitelistConfig, get_config, MatcherMode, set_config


def setup_logging(verbose: bool = False, log_file: Optional[Path] = None) -> None:
    level = "DEBUG" if verbose else "WARNING"
    handlers: list[logging.Handler] = [
        RichHandler(rich_tracebacks=True, console=console, show_time=False)
    ]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    logging.basicConfig(level=level, format="%(message)s", handlers=handlers)


def _print_status(message: str) -> None:
    console.print(f"[bold cyan]⚡ {message}[/bold cyan]")


def analyze_file(
    file_path: Path,
    case_dir: Path,
    no_ai: bool = False,
    ai_config: Optional[AIProviderConfig] = None,
    no_mitre: bool = False,
    status_callback: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    log = status_callback or _print_status

    log(f"Loading {file_path.name}")
    logger.info("Analyzing file: %s", file_path)
    try:
        email_data: EmailData = parse_email(file_path)
    except Exception as exc:
        logger.error("Failed to parse %s: %s", file_path, exc)
        return {"file": str(file_path), "error": str(exc)}

    log("Parsing email")
    headers_str = "\n".join(f"{k}: {v}" for k, v in email_data.headers.items())
    combined_text = headers_str + "\n" + email_data.body_text + "\n" + email_data.body_html
    for url in email_data.urls_from_html:
        combined_text += "\n" + url

    log("Extracting IoCs")
    iocs = extract_iocs(combined_text)

    extracted_data = {
        "headers": headers_str,
        "urls": iocs["urls"],
        "domains": iocs["domains"],
        "ips": iocs["ips"],
        "emails": iocs["emails"],
        "body_text": email_data.body_text,
        "body_html": email_data.body_html,
        "forms": email_data.forms,
    }

    log("Running detection engine")
    analysis = analyze_email(extracted_data)

    log("Generating reports")
    report_path = generate_report(email_data.__dict__, iocs, analysis, email_path=file_path, case_dir=case_dir)

    if not no_ai:
        log("Requesting AI explanation")
        ai_explain(extracted_data, analysis, case_dir=case_dir, config=ai_config)

    if not no_mitre:
        mitre_path = case_dir / f"{case_dir.name}_mitre_layer.json"
        generate_mitre_navigator_layer(analysis, case_dir.name, mitre_path)

    return {
        "file": str(file_path),
        "case_dir": str(case_dir),
        "verdict": analysis["verdict"],
        "score": analysis["score"],
        "confidence": _confidence(analysis["score"]),
        "reasons": analysis["reasons"],
        "report": report_path,
        "iocs": iocs,
    }


def _confidence(score: int) -> str:
    if score >= 10:
        return "HIGH"
    if score >= 5:
        return "MEDIUM"
    return "LOW"


def batch_analyze(
    directory: Path,
    output_dir: Path,
    no_ai: bool,
    ai_config: Optional[AIProviderConfig],
    no_mitre: bool,
    status_callback: Optional[Callable[[str], None]] = None,
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    eml_files = sorted(directory.rglob("*.eml"))
    if not eml_files:
        msg = f"No .eml files found in {directory}"
        if status_callback:
            status_callback(msg)
        else:
            console.print(f"[yellow]⚠ {msg}[/yellow]")
        logger.warning("No .eml files found in %s", directory)
        return results

    msg = f"Found {len(eml_files)} .eml files"
    if status_callback:
        status_callback(msg)
    else:
        console.print(f"[cyan]{msg} in {directory}[/cyan]")
    logger.info("Found %d .eml files in %s", len(eml_files), directory)

    for idx, eml_path in enumerate(eml_files, 1):
        try:
            if status_callback:
                status_callback(f"Analyzing ({idx}/{len(eml_files)}): {eml_path.name}")
            file_case_dir = output_dir / eml_path.stem
            result = analyze_file(
                eml_path,
                file_case_dir,
                no_ai=no_ai,
                ai_config=ai_config,
                no_mitre=no_mitre,
                status_callback=status_callback,
            )
            results.append(result)
        except Exception as exc:
            logger.error("Failed to analyze %s: %s", eml_path, exc)
            results.append({"file": str(eml_path), "error": str(exc)})

    summary_path = output_dir / "batch_summary.json"
    with open(summary_path, "w", encoding="utf-8") as fh:
        json.dump(
            {"generated_at": time.strftime("%Y-%m-%d %H:%M:%S"), "results": results},
            fh,
            indent=2,
            default=str,
        )
    logger.info("Batch summary written to %s", summary_path)
    return results


def monitor_directory(
    directory: Path,
    output_dir: Path,
    no_ai: bool,
    ai_config: Optional[AIProviderConfig],
    no_mitre: bool,
) -> None:
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
    except ImportError:
        logger.error("watchdog is required for monitoring mode. Install with: pip install watchdog")
        sys.exit(1)

    class Handler(FileSystemEventHandler):
        def on_created(self, event):  # type: ignore[override]
            if not event.is_directory and event.src_path.endswith(".eml"):
                logger.info("New file detected: %s", event.src_path)
                try:
                    case_dir = output_dir / Path(event.src_path).stem
                    analyze_file(
                        Path(event.src_path),
                        case_dir,
                        no_ai=no_ai,
                        ai_config=ai_config,
                        no_mitre=no_mitre,
                    )
                except Exception as exc:
                    logger.error("Failed to analyze %s: %s", event.src_path, exc)

    event_handler = Handler()
    observer = Observer()
    observer.schedule(event_handler, str(directory), recursive=False)
    observer.start()
    logger.info("Monitoring directory %s for new .eml files. Press Ctrl+C to stop.", directory)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


def _verdict_style(verdict: str) -> str:
    if verdict == "PHISHING":
        return "bold red"
    if verdict == "SUSPICIOUS":
        return "bold yellow"
    return "bold green"


def _print_summary(result: Dict[str, Any]) -> None:
    if "error" in result:
        console.print(f"[red]✗ Analysis failed:[/red] {result['error']}")
        return

    verdict = result["verdict"]
    style = _verdict_style(verdict)

    summary = Table(show_header=False, box=None, padding=(0, 2))
    summary.add_column("Key", style="bold cyan", no_wrap=True)
    summary.add_column("Value")
    summary.add_row("Case ID", result.get("case_dir", "N/A").split("/")[-1])
    summary.add_row("Email", Path(result["file"]).name)
    summary.add_row("Verdict", Text(verdict, style=style))
    summary.add_row("Score", f"{result['score']} / 20")
    summary.add_row("Confidence", result["confidence"])

    iocs = result.get("iocs", {})
    summary.add_row("URLs", str(len(iocs.get("urls", []))))
    summary.add_row("Domains", str(len(iocs.get("domains", []))))
    summary.add_row("IPs", str(len(iocs.get("ips", []))))
    summary.add_row("Emails", str(len(iocs.get("emails", []))))

    console.print(Panel(summary, title="[bold]Investigation Summary[/bold]", border_style="blue", padding=(1, 2)))

    if result.get("reasons"):
        reasons = Table(show_header=False, box=None, padding=(0, 2))
        reasons.add_column("•", style="bold red", no_wrap=True)
        for reason in result["reasons"]:
            reasons.add_row(reason)
        console.print(Panel(reasons, title="[bold red]Detection Reasons[/bold red]", border_style="red", padding=(1, 2)))

    console.print(f"[green]📁 Reports saved to:[/green] [cyan]{result.get('case_dir', 'N/A')}[/cyan]")
    if result.get("report"):
        console.print(f"   [green]✓[/green] Text: [cyan]{Path(result['report']).name}[/cyan]")
    mitre_name = f"{Path(result.get('case_dir', '')).name}_mitre_layer.json"
    mitre_path = Path(result.get("case_dir", "")) / mitre_name
    if mitre_path.exists():
        console.print(f"   [green]✓[/green] MITRE: [cyan]{mitre_name}[/cyan]")


def _print_batch_summary(results: List[Dict[str, Any]]) -> None:
    phish_count = sum(1 for r in results if r.get("verdict") == "PHISHING")
    susp_count = sum(1 for r in results if r.get("verdict") == "SUSPICIOUS")

    table = Table(title="Batch Investigation Summary", show_header=True, header_style="bold magenta")
    table.add_column("Email", style="cyan", no_wrap=True)
    table.add_column("Verdict", style="bold")
    table.add_column("Score", justify="right")
    table.add_column("Confidence")

    for r in results:
        verdict = r.get("verdict", "ERROR")
        style = _verdict_style(verdict)
        table.add_row(
            Path(r.get("file", "?")).name,
            Text(verdict, style=style),
            str(r.get("score", "-")),
            r.get("confidence", "-"),
        )

    console.print(table)
    console.print(f"[green]Total:[/green] {len(results)} files  |  [red]Phishing:[/red] {phish_count}  |  [yellow]Suspicious:[/yellow] {susp_count}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="phishx",
        description="Automated phishing email investigation tool for SOC teams",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  phishx sample.eml
  phishx sample.eml --format json
  phishx ./inbox --output ./reports
  phishx sample.eml --no-ai
  phishx ./maildir --monitor
        """,
    )
    parser.add_argument("input", type=Path, nargs="?", help="Path to .eml file or directory of .eml files")
    parser.add_argument("-o", "--output", type=Path, default=Path("reports"), help="Output directory (default: reports)")
    parser.add_argument("--no-ai", action="store_true", help="Disable AI explanation generation")
    parser.add_argument("--ai-provider", choices=["ollama", "openai", "anthropic"], default="ollama", help="AI provider (default: ollama)")
    parser.add_argument("--ai-model", default="llama3.2", help="AI model name (default: llama3.2)")
    parser.add_argument("--ai-api-key", default=None, help="API key for OpenAI/Anthropic")
    parser.add_argument("--ai-base-url", default="http://127.0.0.1:11434", help="Base URL for Ollama (default: http://127.0.0.1:11434)")
    parser.add_argument("--no-mitre", action="store_true", help="Skip MITRE ATT&CK Navigator layer generation")
    parser.add_argument("--whitelist", type=Path, default=None, help="Path to custom whitelist file")
    parser.add_argument("--whitelist-mode", choices=["exact", "subdomain"], default="subdomain", help="Whitelist matching mode (default: subdomain)")
    parser.add_argument("--format", choices=["text", "json", "both"], default="both", help="Report format (default: both)")
    parser.add_argument("--monitor", action="store_true", help="Monitor directory for new .eml files")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    parser.add_argument("--log-file", type=Path, default=None, help="Write logs to file")
    parser.add_argument("--sound", action="store_true", help="Enable sound alerts for critical findings")
    parser.add_argument("--db", type=Path, default=Path("phishx_memory.db"), help="Path to investigation memory database (default: phishx_memory.db)")

    args = parser.parse_args(argv)

    setup_logging(verbose=args.verbose, log_file=args.log_file)
    logger.info("Starting phishing investigator")

    if args.whitelist:
        mode = MatcherMode.EXACT if args.whitelist_mode == "exact" else MatcherMode.SUBDOMAIN
        set_config(WhitelistConfig(path=args.whitelist, mode=mode))
        console.print(f"[green]✓[/green] Whitelist loaded: [cyan]{args.whitelist}[/cyan] [dim](mode: {args.whitelist_mode})[/dim]")
        logger.info("Custom whitelist loaded from %s (mode=%s)", args.whitelist, args.whitelist_mode)

    if not args.input and not args.monitor:
        ai_config = AIProviderConfig(
            provider=args.ai_provider,
            api_key=args.ai_api_key,
            model=args.ai_model,
            base_url=args.ai_base_url,
        )
        from console import start_console
        start_console(output_dir=args.output, ai_config=ai_config, sound=args.sound, db_path=args.db)
        return 0

    args.output.mkdir(parents=True, exist_ok=True)

    ai_config = AIProviderConfig(
        provider=args.ai_provider,
        api_key=args.ai_api_key,
        model=args.ai_model,
        base_url=args.ai_base_url,
    )

    if args.monitor:
        if not args.input.is_dir():
            console.print("[red]✗ Monitor mode requires a directory input[/red]")
            return 1
        console.print(f"[cyan]👁 Monitoring:[/cyan] {args.input}")
        monitor_directory(args.input, args.output, args.no_ai, ai_config, args.no_mitre)
        return 0

    if args.input.is_dir():
        results = batch_analyze(args.input, args.output, args.no_ai, ai_config, args.no_mitre, status_callback=_print_status)
        console.print()
        _print_batch_summary(results)
        return 0

    if not args.input.exists():
        console.print(f"[red]✗ Input file not found:[/red] {args.input}")
        return 1

    try:
        case_dir = generate_case_directory(args.input, {})
        result = analyze_file(
            args.input,
            case_dir,
            no_ai=args.no_ai,
            ai_config=ai_config,
            no_mitre=args.no_mitre,
            status_callback=_print_status,
        )

        console.print()
        _print_summary(result)

        if "error" not in result:
            try:
                from memory.database import get_db
                from memory.dna import compute_threat_dna
                db = get_db(args.db)
                db.save_case(
                    case_id=case_dir.name,
                    email_path=str(args.input),
                    case_dir=str(case_dir),
                    verdict=result.get("verdict", "UNKNOWN"),
                    score=result.get("score", 0),
                    confidence=result.get("confidence", "LOW"),
                )
                db.save_iocs(case_dir.name, result.get("iocs", {}))
                if result.get("iocs") is not None:
                    pass
            except Exception as exc:
                logger.warning("Failed to persist case to database: %s", exc)

        if "error" in result:
            return 1

        if args.format == "text":
            console.print()
            with open(case_dir / f"{case_dir.name}.txt", "r", encoding="utf-8") as fh:
                console.print(fh.read())
        elif args.format == "json":
            console.print()
            safe = json.loads(json.dumps(result, default=str))
            console.print_json(data=safe)
        else:
            console.print()
            info = Table(show_header=False, box=None, padding=(0, 2))
            info.add_column("Key", style="dim")
            info.add_column("Value", style="cyan")
            info.add_row("Case directory", result.get("case_dir", "N/A"))
            info.add_row("Report file", result.get("report", "N/A"))
            console.print(Panel(info, title="[bold]Output Files[/bold]", border_style="dim blue", padding=(1, 2)))
        return 0
    except Exception as exc:
        console.print(f"[red]✗ Analysis failed:[/red] {exc}")
        logger.error("Analysis failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
