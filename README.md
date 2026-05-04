# 5G Core MASIAT

5G Core MASIAT is a **5G Core API security testing platform** built for demonstrating **injection vulnerabilities, authentication weaknesses, and authorization flaws** in Service-Based Interfaces (SBI).

It combines:

- a **FastAPI dashboard** for live demonstrations
- a **scanner API** for structured runs
- a **scanner CLI** for command-line operation
- a **modular checks / attacks layer** inspired by telecom security workflows
- **evidence storage and reports** for findings, run history, and demo output

The project is designed for academic demonstrations, practical security labs, and explaining how **vulnerable** and **secure** API behavior differ inside a 5G Core context.

## What This Project Demonstrates

- SQL-style injection on subscriber lookups
- NoSQL / JSON injection behavior
- SUPI manipulation scenarios
- command injection simulation on diagnostics flows
- JWT manipulation and token verification
- BOLA-style object access issues
- NRF registration / spoofing logic
- OpenAPI-guided fuzz input generation
- structured scan runs with saved findings

## Main 5G-Inspired Components

- **NRF**: service discovery and registration
- **UDM**: subscriber lookup and data access
- **NEF**: exposed diagnostics / service logic
- **AUSF / PCF / AMF / SMF**: scanner-side modules for broader telecom-style workflows

## Project Architecture

There are two main usage paths:

1. **Dashboard path**
   - Open the web UI
   - run attacks interactively
   - review secure vs vulnerable outputs
   - view fuzzing, lab blueprint, sources, and playbook

2. **Scanner path**
   - launch structured scans from the dashboard or CLI
   - run modular checks and attack modules
   - export JSON reports and network-map-style output

## Repository Structure

```text
5G-Core-MASIAT/
├─ app/
│  ├─ main.py
│  ├─ config.py
│  ├─ database.py
│  ├─ schemas.py
│  ├─ security.py
│  ├─ telecom_security.py
│  ├─ data/
│  ├─ routers/
│  │  ├─ analysis.py
│  │  ├─ dashboard.py
│  │  ├─ nef.py
│  │  ├─ nrf.py
│  │  ├─ scanner.py
│  │  ├─ tester.py
│  │  └─ udm.py
│  ├─ static/
│  │  ├─ css/styles.css
│  │  └─ js/app.js
│  └─ templates/
│     └─ index.html
├─ analyzer/
│  └─ response.py
├─ checks/
│  ├─ base_check.py
│  ├─ compat.py
│  ├─ amf/
│  ├─ ausf/
│  ├─ nrf/
│  ├─ oauth/
│  ├─ pcf/
│  ├─ smf/
│  └─ udm/
├─ attacks/
│  ├─ base_attack.py
│  ├─ ausf/
│  ├─ nrf/
│  ├─ pcf/
│  └─ udm/
├─ core/
│  ├─ database.py
│  ├─ models.py
│  ├─ payload_loader.py
│  └─ scanner_engine.py
├─ config/
│  └─ profiles/
├─ report/
│  ├─ reporter.py
│  ├─ visualizer.py
│  ├─ report.json
│  ├─ attack_report.json
│  └─ network_map.html
├─ docs/
│  ├─ 5g_project_presentation.html
│  ├─ 5g_project_demo_guide.pdf
│  └─ REAL_5G_LAB_BLUEPRINT.md
├─ uploads/
├─ tests/
│  └─ test_security_lab.py
├─ main.py
├─ scanner_cli.py
├─ config.py
├─ requirements.txt
└─ README.md
```

## Requirements

- Python 3.10+ recommended
- Windows, Linux, or WSL

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## How To Run

### Option 1: Run the dashboard

From the project root:

```bash
python -m uvicorn app.main:app --reload
```

Then open:

```text
http://127.0.0.1:8000
```

### Option 2: Run the class-style scanner CLI

```bash
python main.py --mode scan
python main.py --mode scan --nf UDM
python main.py --mode attack --module udm
```

### Option 3: Run the structured scanner CLI

```bash
python scanner_cli.py profiles list
python scanner_cli.py modules list
python scanner_cli.py run --profile mock-local-lab --mode dry-run
python scanner_cli.py run --profile mock-local-lab --mode active
```

## Dashboard Features

The dashboard includes:

- **Attack Surface** overview
- **interactive attack runner**
- **structured scan launcher**
- **recent runs** viewer
- **attack catalog**
- **OpenAPI fuzz payload generation**
- **lab blueprint**
- **JWT verification**
- **implementation playbook**
- **research sources**
- **scenario upload**

### Main dashboard routes

- `GET /`
- `GET /api/overview`

### Security testing routes

- `POST /api/tester/run`
- `GET /api/tester/payloads`
- `GET /api/tester/report`
- `POST /api/tester/upload`

### Analysis routes

- `GET /api/analysis/lab`
- `GET /api/analysis/catalog`
- `GET /api/analysis/playbook`
- `GET /api/analysis/sources`
- `GET /api/analysis/stride`
- `GET /api/analysis/openapi`
- `GET /api/analysis/fuzz`
- `GET /api/analysis/oauth/sample`
- `POST /api/analysis/oauth/verify`

### Scanner routes

- `GET /api/scanner/profiles`
- `GET /api/scanner/modules`
- `GET /api/scanner/runs`
- `GET /api/scanner/runs/{run_id}`
- `GET /api/scanner/audit`
- `POST /api/scanner/run`

## Demo API Key

Some secure flows expect:

```text
x-api-key: 5GC-SECURE-2026
```

## Demo Flow

This is the recommended live demonstration order.

### 1. Start the application

```bash
cd D:\5G-Core-MASIAT
python -m uvicorn app.main:app --reload
```

### 2. Open the dashboard

Open:

```text
http://127.0.0.1:8000
```

### 3. Introduce the project

Suggested line:

> My project is a 5G Core API security testing platform. It demonstrates how vulnerable and secure microservice APIs behave under injection, authentication, and authorization attacks.

### 4. Explain the 5G Core focus

Suggested line:

> I focus on Service-Based Interfaces inside the 5G Core, especially APIs inspired by NRF, UDM, and NEF.

### 5. Show the Attack Surface section

Explain that it gives:

- simulated 5G asset visibility
- API exposure indicators
- security risk metrics

### 6. Run the first live dashboard attack

Best first choice:

- `Load Command Sample`
- `Run Injection Test`

Explain:

> The vulnerable path shows unsafe command construction, while the secure path blocks malicious input.

### 7. Run a second dashboard attack

Best options:

- `Load SUPI Injection`
- `Load JSON Injection`

Explain:

> This demonstrates how subscriber-related or JSON-based input can affect weak API logic while the secure implementation validates and blocks it.

### 8. Show structured scanning

- keep the default selected modules
- click `Launch Structured Scan`
- open `Recent Runs`

Explain:

> Structured scan mode launches multiple predefined checks and stores the findings as formal scan evidence.

### 9. Show the analysis sections

Use:

- `Refresh Catalog`
- `Refresh Fuzz`
- `Show Lab`
- `Verify JWT`
- `Show Playbook`
- `Show Sources`

Explain that these connect the practical testing workflow to:

- OpenAPI discovery
- lab deployment logic
- token security
- implementation guidance
- research references

### 10. Switch to the CLI

```bash
python main.py --mode scan
python main.py --mode scan --nf UDM
python main.py --mode attack --module udm
```

Then show the structured engine:

```bash
python scanner_cli.py profiles list
python scanner_cli.py run --profile mock-local-lab --mode dry-run
```

## Reports and Evidence

This project stores evidence in the local database and report files.

Generated report artifacts include:

- [report/report.json](D:/5G-Core-MASIAT/report/report.json)
- [report/attack_report.json](D:/5G-Core-MASIAT/report/attack_report.json)
- [report/network_map.html](D:/5G-Core-MASIAT/report/network_map.html)

Useful output areas:

- dashboard result panel
- dashboard attack history
- recent structured runs
- exported JSON reports

## Documentation Assets

Presentation and demo materials:

- [docs/5g_project_presentation.html](D:/5G-Core-MASIAT/docs/5g_project_presentation.html)
- [docs/5g_project_demo_guide.pdf](D:/5G-Core-MASIAT/docs/5g_project_demo_guide.pdf)
- [docs/REAL_5G_LAB_BLUEPRINT.md](D:/5G-Core-MASIAT/docs/REAL_5G_LAB_BLUEPRINT.md)

## Testing

Run the automated test suite:

```bash
python -m pytest
```

## Docker

Build and run with Docker Compose:

```bash
docker compose up --build
```

Then open:

```text
http://127.0.0.1:8000
```

## Practical Notes

- This project is designed as a **contained academic security lab**
- it demonstrates realistic API security logic without requiring a live production 5G Core
- it is suitable for:
  - viva demonstrations
  - lab reports
  - secure vs vulnerable comparisons
  - scanner workflow demonstrations

## Future Improvements

- integrate with real free5GC or Open5GS traffic
- add stronger OAuth2 or mTLS service-to-service trust
- expand fuzzing coverage
- improve PDF / report export
- add more telecom-specific attack modules

## One-Sentence Summary

> 5G Core MASIAT is a practical platform for demonstrating how API vulnerabilities can affect 5G Core microservices and how secure controls can detect, block, and explain those attacks.

