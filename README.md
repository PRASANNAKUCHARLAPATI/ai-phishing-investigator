# PHISHX

Open-source AI Investigation Platform for Phishing, Campaign Correlation, and SOC Automation.

> "One Email. One Investigation. One Campaign. Everything Connected."

![Python](https://img.shields.io/badge/python-3.9+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## Highlights

- Offline-first AI investigation platform
- Interactive SOC console inspired by Metasploit
- Local AI support through Ollama
- Threat DNA fingerprinting
- Campaign correlation engine
- Investigation memory using SQLite
- Free OSINT integrations
- Automatic Sigma/YARA/Suricata rule generation
- MITRE ATT&CK mapping

## Why PHISHX?

PHISHX is an offline-first AI-powered phishing investigation platform built for Security Operations Centers (SOC), DFIR teams, and threat hunters.

Instead of simply classifying phishing emails, PHISHX reconstructs attacker infrastructure, correlates related phishing campaigns, builds investigation knowledge, and assists analysts throughout the investigation lifecycle.

Every analyzed email becomes part of a continuously growing investigation database, allowing analysts to discover relationships between infrastructure, phishing kits, domains, senders, and campaigns over time.

The platform is designed to work entirely with open-source technologies and local AI models, making enterprise-grade phishing investigations accessible without paid APIs.

## What PHISHX Does

PHISHX transforms phishing investigation from a one-off scan into a persistent intelligence workflow:

1. **Investigate** — Parse emails, extract IOCs, run detection rules, and generate reports
2. **Remember** — Every case is stored in a local SQLite database with full IOC history
3. **Correlate** — Threat DNA fingerprinting links related emails and campaigns automatically
4. **Enrich** — Free OSINT integrations (URLhaus, AbuseIPDB, CISA KEV, RDAP, etc.) without paid APIs
5. **Automate** — Generate Sigma, YARA, and Suricata rules directly from investigation results
6. **Assist** — On-demand AI Q&A via Ollama, OpenAI, or Anthropic

This turns PHISHX from a "phishing scanner" into a SOC investigation assistant that gets smarter with every email analyzed.

### Architecture

```
                 Email (.eml)
                      │
                      ▼
              Email Parsing Engine
                      │
          ┌───────────┴────────────┐
          ▼                        ▼
    IOC Extraction          HTML Analysis
          │                        │
          └───────────┬────────────┘
                      ▼
              Detection Engine
                      │
        ┌─────────────┼──────────────┐
        ▼             ▼              ▼
 Threat Intel     Threat DNA      AI Engine
        │             │              │
        └─────────────┴──────────────┘
                      ▼
            Investigation Memory
                      │
      ┌───────────────┼────────────────┐
      ▼               ▼                ▼
 Campaigns      Reports           Rule Generator
```

## Why PHISHX is Different

| Traditional Phishing Tool | PHISHX |
|---------------------------|--------|
| Analyze one email | Builds long-term investigation memory |
| IOC extraction | IOC correlation across cases |
| Static reports | Interactive investigation console |
| Simple verdict | AI-assisted investigation |
| No context | Campaign intelligence |
| No rule generation | Generates Sigma/YARA/Suricata |
| One investigation | Continuous knowledge base |

## Implemented Features

### Interactive SOC Console

A Metasploit-inspired investigation console for phishing analysis.

```bash
phishx
```

```
phishx > load sample.eml
✓ Loaded sample.eml

phishx(sample.eml) > analyze
[1/6] Parsing email... ✓
[2/6] Extracting IoCs... ✓
[3/6] Authentication checks... ✓
[4/6] Running detection rules... ✓
[5/6] Threat intelligence... ✓
[6/6] Report generation... ✓

phishx(sample.eml) > summary
phishx(sample.eml) > urls
phishx(sample.eml) > intel urlhaus
phishx(sample.eml) > intel history https://evil.com/login
phishx(sample.eml) > intel osint abuseipdb
phishx(sample.eml) > dna
phishx(sample.eml) > campaign
phishx(sample.eml) > relationships
phishx(sample.eml) > rules sigma
phishx(sample.eml) > note "Escalate to IR team"
phishx(sample.eml) > ask "Why is this phishing?"
phishx(sample.eml) > exit
```

### Available Commands

| Command | Description |
|---------|-------------|
| `load <path>` | Load `.eml` file or directory |
| `analyze` | Run full investigation on loaded case |
| `summary` | Show investigation summary with threat meter |
| `urls` / `domains` / `ips` | List extracted indicators |
| `headers` / `forms` / `attachments` | Drill into email structure |
| `mitre` | Show MITRE ATT&CK mapping |
| `intel urlhaus` | Enrich IoCs with URLhaus |
| `intel virustotal --api-key KEY` | Enrich IoCs with VirusTotal |
| `intel history <ioc>` | Look up IOC history in local DB |
| `intel osint <provider>` | Query free OSINT (abuseipdb, rdap, doh, phishtank, alienvault-otx, cisa-kev) |
| `dna` | Show threat DNA fingerprint and similar cases |
| `campaign` | Show linked campaigns or related cases |
| `relationships` | Show related cases from memory |
| `rules [sigma\|yara\|suricata\|all]` | Generate detection rules |
| `note <text>` | Add analyst note to case |
| `cases` / `use <id>` | Multi-case workspace management |
| `history` / `clear` | Session utilities |
| `ask <question>` | Ask the AI assistant about the case |
| `exit` | Exit console |

### Email Forensics

Complete email parsing supporting:

- Header analysis (Received, Authentication-Results, From, Reply-To, etc.)
- MIME structure parsing
- HTML body extraction and link harvesting
- Credential harvesting form detection
- Attachment analysis with MD5/SHA-256 hashing
- URL extraction from HTML attributes (`href`, `src`, `data-src`)
- Email authentication validation (SPF, DKIM, DMARC)

### Detection Engine

Pluggable rule-based detection covering:

- Email authentication failures (SPF, DKIM, DMARC)
- Suspicious infrastructure (Linux hosts, root users, Postfix anomalies)
- Reply-To mismatches
- Brand impersonation (lookalike domains)
- Suspicious TLDs and unusually long domains
- Cloud VPS IP detection (DigitalOcean, Hetzner, AWS, GCP, Azure)
- Fear and urgency language
- Credential-harvesting HTML forms
- URL obfuscation (punycode, excessive subdomains, long random domains)

### Investigation Memory (SQLite)

Every investigation is persisted locally:

- Cases with verdicts, scores, and timestamps
- IOC history with seen counts across investigations
- Analyst notes per case
- Case relationships and similarity links
- Campaign tracking tables

Database location: `phishx_memory.db` (configurable via `--db`)

### Threat DNA

Per-email fingerprinting computed during analysis:

- HTML hash
- CSS signature
- Subject pattern (normalized)
- Sender domain
- Sender timezone
- Attachment MIME types
- Form action domains
- URL patterns (standard, punycode, long-random, excessive-subdomains)
- Verdict and detection reasons

DNA enables similarity search across investigations.

### Free OSINT Integration

No paid APIs required. Built-in providers:

- **URLhaus** — URL reputation (no key required)
- **PhishTank** — Phishing URL database
- **AbuseIPDB** — IP abuse scoring (optional key)
- **AlienVault OTX** — Threat intelligence pulses (optional key)
- **CISA KEV** — Known exploited vulnerabilities catalog
- **RDAP** — Registration data for IPs/domains
- **DNS over HTTPS** — Domain resolution via Google DNS
- **crt.sh** — Certificate transparency logs

### Detection Rule Generator

Automatically generates detection content from investigation results:

- **Sigma** — SIEM detection rules (splunk, elastic, sentinel, etc.)
- **YARA** — File-based detection rules
- **Suricata** — Network IDS rules

### AI Assistant

On-demand AI analysis via multiple providers:

- **Ollama** (default, local, streaming)
- **OpenAI** (GPT-4o, etc.)
- **Anthropic** (Claude)

Supports investigative questions like "Why is this phishing?", "Explain the infrastructure", and "What should the SOC do next?"

### Report Generation

Multiple output formats:

- Text report (human-readable)
- JSON report (SIEM-ready)
- MITRE ATT&CK Navigator layer
- AI explanation (appended to text report)

### Batch & Monitoring Modes

```bash
# Analyze all .eml files in a directory
./phishx ./incoming_emails --output ./reports

# Monitor a directory for new emails
./phishx ./maildir --monitor
```

## Technology Stack

### Backend
- Python 3.9+

### Console
- Rich

### Parsing
- email (stdlib)
- BeautifulSoup
- lxml

### Database
- SQLite

### AI
- Ollama
- OpenAI
- Anthropic

### Threat Intelligence
- URLhaus
- PhishTank
- AbuseIPDB
- AlienVault OTX
- CISA KEV

### Detection Engineering
- Sigma
- YARA
- Suricata

### Testing
- pytest

## Installation

```bash
# Clone the repository
git clone https://github.com/PRASANNAKUCHARLAPATI/ai-phishing-investigator.git
cd ai-phishing-investigator

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run
./phishx
```

## Requirements

- Python 3.9+
- Core: `requests`, `beautifulsoup4`, `lxml`, `rich`

## Single-File Analysis

```bash
./phishx sample.eml
./phishx sample.eml --format json
./phishx sample.eml --no-ai
./phishx sample.eml --intel-provider virustotal --intel-api-key YOUR_KEY
```

## Database & Sound Options

```bash
# Custom database path
./phishx sample.eml --db ./cases/memory.db

# Enable sound alerts for critical findings
./phishx --sound
```

## MITRE ATT&CK Mapping

- T1566.002 — Phishing: Link
- T1583.001 — Acquire Infrastructure: Domains
- T1583.003 — Acquire Infrastructure: VPS
- T1056.004 — Input Capture: Credential Phishing

## AI Configuration

### Ollama (local, default)

```bash
ollama pull llama3.2
./phishx --ai-provider ollama --ai-model llama3.2
```

### OpenAI

```bash
export OPENAI_API_KEY="sk-..."
./phishx --ai-provider openai --ai-model gpt-4o
```

### Anthropic

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
./phishx --ai-provider anthropic --ai-model claude-sonnet-4-20250514
```

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## Development

```bash
pip install -e .
ruff check .
ruff format .
```

## Contributing

Contributions are welcome.

If you have ideas for new detection rules, threat intelligence providers, campaign correlation techniques, or AI investigation workflows, feel free to open an issue or submit a pull request.

## Disclaimer

PHISHX is intended for defensive security, malware analysis, phishing investigation, incident response, and educational purposes only.

The project is not intended to facilitate unauthorized access or offensive cyber operations.

## License

MIT License

---

## Roadmap

The following capabilities are planned but not yet implemented in this branch:

### Phase 1 — Intelligence Layer
- [ ] FAISS-powered semantic similarity search across Threat DNA
- [ ] Sentence-transformers embeddings for IOC and case clustering
- [ ] Automated campaign detection via graph clustering (NetworkX)
- [ ] crt.sh integration for certificate transparency lookups
- [ ] Shodan InternetDB integration
- [ ] Automated registrar and hosting provider enrichment (RDAP expansion)

### Phase 2 — Advanced Console Commands
- [ ] `graph` — Render knowledge graph inline in terminal
- [ ] `hunt` — Run hypothesis-driven IOC hunting across memory
- [ ] `story` — AI-generated attack narrative from investigation evidence
- [ ] `compare <case-id>` — Side-by-side case comparison with AI
- [ ] `campaign create` / `campaign merge` — Manual and AI-assisted campaign management
- [ ] `export pdf` / `export html` — Additional report formats
- [ ] `timeline` — Investigation event timeline view

### Phase 3 — AI Investigation Engine
- [ ] Context-aware AI that reasons over full case history, not just single investigations
- [ ] Predictive threat hunting suggestions
- [ ] Automated rule tuning based on false-positive feedback
- [ ] Executive summary generation for non-technical stakeholders
- [ ] IOC prioritization and enrichment recommendations

### Phase 4 — Detection Engineering
- [ ] Wazuh rule generation
- [ ] Zeek/Bro script generation
- [ ] Splunk SPL generation
- [ ] Elasticsearch query generation
- [ ] STIX/TAXII export for threat intelligence sharing

### Phase 5 — Visualization
- [ ] FastAPI backend for web-based dashboard
- [ ] Knowledge graph visualization (D3.js / vis.js)
- [ ] Campaign timeline charts
- [ ] IOC heatmaps and infrastructure maps
- [ ] Investigation workspace UI

### Phase 6 — Platform Integration
- [ ] TheHive / Cortex integration
- [ ] Wazuh SIEM integration
- [ ] MISP import/export
- [ ] Slack/PagerDuty alerting
- [ ] Docker / Kubernetes deployment
