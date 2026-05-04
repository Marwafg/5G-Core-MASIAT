# 5G Core Microservice API Security & Injection Attack Tester

This project is an **OpenAPI-driven 5G Core microservice API security platform** that focuses on **injection vulnerabilities and authorization flaws** in service-based interfaces.

Official intro:

> This project focuses on testing security vulnerabilities in 5G Core microservice APIs, specifically injection attacks and authorization flaws, using OpenAPI-based discovery and automated testing.

Instead of showing security only in theory, the project gives a side-by-side comparison:

- **Vulnerable APIs** that use unsafe patterns such as SQL string concatenation, unvalidated JSON merging, or weak token handling.
- **Secure APIs** that apply API authentication checks, allowlist validation, parameterized queries, and authorization controls.
- **An OpenAPI-driven attack runner dashboard** that discovers inputs and executes API security tests visually.

## Why This Project Stands Out

- It uses real 5G-core-inspired components: **NRF**, **UDM**, and **NEF**.
- It demonstrates both **API security** and **automated injection testing** in one polished app.
- It includes a clean UI for live presentations and viva demonstrations.
- It records attack history so you can show measurable testing evidence.
- It is **specification-driven**, using OpenAPI concepts rather than random payload guessing.

## Architecture

### Simulated 5G Core Services

- **NRF**: service registry where microservices are listed.
- **UDM**: subscriber data management API used for lookup operations.
- **NEF**: network exposure API used for diagnostics.

### Security Focus

- OpenAPI-based input discovery.
- JSON and SUPI injection testing.
- API authentication validation through JWT-focused checks.
- Object-level authorization testing.
- Payload evaluation with risk scoring and attack indicators.

## Main Features

1. **Dashboard UI**
   - Presents service health, API risk metrics, recent test evidence, and the testing lab.
2. **JSON / NoSQL Injection Testing**
   - Tests JSON-based APIs with payloads such as `{"supi":{"$ne": null}}`.
3. **SUPI Injection Testing**
   - Simulates injection against subscriber identity fields such as `"supi": "' OR 1=1 --"`.
4. **OpenAPI-Guided Fuzzing**
   - Parses a 3GPP-style SBI spec and generates malformed payloads automatically.
5. **API Authentication Validation**
   - Tests JWT robustness, tampered claims, and NF-to-NF token validation behavior.
6. **Object-Level Authorization Testing**
   - Demonstrates BOLA-style access to unauthorized subscriber or NF objects.
7. **Presentation-Friendly Design**
   - Strong narrative for explaining API security, exploit path, and mitigation.

## Project Structure

```text
app/
  main.py
  database.py
  security.py
  schemas.py
  routers/
    dashboard.py
    nef.py
    nrf.py
    tester.py
    udm.py
  static/
    css/styles.css
    js/app.js
  templates/
    index.html
tests/
  test_security_lab.py
requirements.txt
README.md
```

## How To Run

### 1. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 2. Start the app

```bash
python -m uvicorn app.main:app --reload
```

### 3. Open the dashboard

Visit:

```text
http://127.0.0.1:8000
```

## Docker Deployment

Run the full application in a container:

```bash
docker compose up --build
```

The app will be available at:

```text
http://127.0.0.1:8000
```

Useful operational endpoints:

- `GET /health`
- `GET /health/ready`
- `GET /api/tester/report`

## Demo API Key

Use this header for secure endpoints:

```text
x-api-key: 5GC-SECURE-2026
```

## Important API Endpoints

### Dashboard and overview

- `GET /`
- `GET /api/overview`

### NRF

- `GET /api/nrf/services`
- `POST /api/nrf/services` (secure)

### UDM subscriber lookup

- `GET /api/udm/vulnerable/subscribers?q=...`
- `GET /api/udm/secure/subscribers?q=...` (secure)

### NEF diagnostics

- `GET /api/nef/vulnerable/diagnostics?target=...`
- `GET /api/nef/secure/diagnostics?target=...` (secure)

### Attack runner

- `GET /api/tester/payloads`
- `POST /api/tester/run`
- `GET /api/tester/report`

### Security analysis

- `GET /api/analysis/lab`
- `GET /api/analysis/stride`
- `GET /api/analysis/openapi`
- `GET /api/analysis/fuzz`
- `GET /api/analysis/oauth/sample`
- `POST /api/analysis/oauth/verify`

## Suggested Presentation Flow

1. Introduce the project as **Injection Testing on 5G Core APIs**.
2. Show OpenAPI parsing and explain that the attack surface is extracted automatically.
3. Run the primary tests:
   - JSON injection
   - SUPI injection
   - OpenAPI-guided fuzzing
4. Then show secondary vulnerabilities:
   - JWT misuse
   - BOLA
5. Explain the mitigations:
   - schema validation
   - parameterized queries
   - API authentication validation
   - object-level authorization checks
6. End with the dashboard history and risk scoring to show measurable API security testing.

## Testing

Run:

```bash
python -m pytest
```

## Future Enhancements

- Add JWT or OAuth2 for service-to-service trust.
- Add rate limiting and API gateway policies.
- Extend the lab with XSS, SSRF, or broken access control cases.
- Export attack reports as PDF for instructors.

## Academic Framing

If you want to describe the project in one sentence:

> Unlike traditional security tools, our platform focuses specifically on injection vulnerabilities in 5G Core APIs by leveraging OpenAPI specifications and simulating realistic microservice interactions.
