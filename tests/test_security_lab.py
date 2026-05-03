from fastapi.testclient import TestClient
import subprocess
import sys

from app.main import app


def test_sql_injection_shows_difference_between_vulnerable_and_secure_modes():
    with TestClient(app) as client:
        vulnerable = client.get(
            "/api/udm/vulnerable/subscribers",
            params={"q": "' OR '1'='1' --"},
        )
        secure = client.get(
            "/api/udm/secure/subscribers",
            params={"q": "' OR '1'='1' --"},
            headers={"x-api-key": "5GC-SECURE-2026"},
        )

    assert vulnerable.status_code == 200
    assert vulnerable.json()["records_returned"] >= 4
    assert secure.status_code == 400


def test_command_injection_secure_endpoint_blocks_payload():
    with TestClient(app) as client:
        vulnerable = client.get(
            "/api/nef/vulnerable/diagnostics",
            params={"target": "8.8.8.8 && whoami"},
        )
        secure = client.get(
            "/api/nef/secure/diagnostics",
            params={"target": "8.8.8.8 && whoami"},
            headers={"x-api-key": "5GC-SECURE-2026"},
        )

    assert vulnerable.status_code == 200
    assert vulnerable.json()["injected_segments"] != ["none"]
    assert secure.status_code == 400


def test_attack_runner_logs_results():
    with TestClient(app) as client:
        response = client.post(
            "/api/tester/run",
            json={"attack_vector": "command_injection", "payload": "8.8.8.8 && whoami"},
        )
        overview = client.get("/api/overview")

    assert response.status_code == 200
    assert overview.status_code == 200
    assert overview.json()["metrics"]["attack_runs"] >= 1


def test_readiness_and_security_headers_are_present():
    with TestClient(app) as client:
        response = client.get("/health/ready")

    assert response.status_code == 200
    assert response.json()["status"] == "ready"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "X-Request-ID" in response.headers


def test_report_export_returns_summary_and_history():
    with TestClient(app) as client:
        client.post(
            "/api/tester/run",
            json={"attack_vector": "sql_injection", "payload": "' OR '1'='1' --"},
        )
        report = client.get("/api/tester/report")

    assert report.status_code == 200
    body = report.json()
    assert body["summary"]["attack_runs"] >= 1
    assert isinstance(body["attack_history"], list)
    assert "attack_succeeds_when" in body["success_criteria"]


def test_analysis_endpoints_return_stride_openapi_and_fuzz_data():
    with TestClient(app) as client:
        stride = client.get("/api/analysis/stride")
        openapi = client.get("/api/analysis/openapi")
        fuzz = client.get("/api/analysis/fuzz")
        playbook = client.get("/api/analysis/playbook")
        sources = client.get("/api/analysis/sources")

    assert stride.status_code == 200
    assert len(stride.json()["model"]) == 6
    assert openapi.status_code == 200
    assert len(openapi.json()["endpoints"]) >= 2
    assert fuzz.status_code == 200
    assert len(fuzz.json()["payloads"]) >= 1
    assert playbook.status_code == 200
    assert len(playbook.json()["sections"]) >= 5
    assert sources.status_code == 200
    assert len(sources.json()["sources"]) >= 5


def test_oauth_verification_blocks_tampered_token():
    with TestClient(app) as client:
        sample = client.get("/api/analysis/oauth/sample")
        verify = client.post(
            "/api/analysis/oauth/verify",
            json={"token": sample.json()["tampered_token"]},
        )

    assert sample.status_code == 200
    assert verify.status_code == 200
    assert verify.json()["status"] == "blocked"


def test_attack_runner_supports_nosql_and_jwt_vectors():
    with TestClient(app) as client:
        nosql = client.post(
            "/api/tester/run",
            json={"attack_vector": "nosql_injection", "payload": '{"$regex": ".*"}'},
        )
        jwt_result = client.post(
            "/api/tester/run",
            json={"attack_vector": "jwt_manipulation", "payload": '{"role":"admin"}'},
        )

    assert nosql.status_code == 200
    assert nosql.json()["vulnerable"]["accepted_operator"] is True
    assert jwt_result.status_code == 200
    assert jwt_result.json()["secure"]["verification"]["status"] == "blocked"


def test_attack_runner_supports_5g_specific_vectors():
    with TestClient(app) as client:
        nrf = client.post(
            "/api/tester/run",
            json={"attack_vector": "nrf_spoofing", "payload": '{"nfType":"AMF","nfInstanceId":"fake-amf-01"}'},
        )
        bola = client.post(
            "/api/tester/run",
            json={"attack_vector": "bola", "payload": "imsi-001010000000002"},
        )
        json_injection = client.post(
            "/api/tester/run",
            json={"attack_vector": "json_injection", "payload": '{"filters":{"$ne":null}}'},
        )
        supi = client.post(
            "/api/tester/run",
            json={"attack_vector": "supi_manipulation", "payload": "imsi-001010000000001' OR '1'='1"},
        )

    assert nrf.status_code == 200
    assert nrf.json()["vulnerable"]["spoofed_nf_registered"] is True
    assert bola.status_code == 200
    assert bola.json()["secure"]["authorization_required"] is True
    assert json_injection.status_code == 200
    assert json_injection.json()["vulnerable"]["json_merged"] is True
    assert supi.status_code == 200
    assert supi.json()["secure"]["format_validated"] is True


def test_simulator_upload_endpoint_accepts_file():
    with TestClient(app) as client:
        response = client.post(
            "/api/tester/upload",
            files={"file": ("scenario.json", b'{"attack":"nrf_spoofing"}', "application/json")},
        )

    assert response.status_code == 200
    assert response.json()["status"] == "uploaded"
    assert response.json()["filename"] == "scenario.json"


def test_dashboard_contains_new_interactive_sections():
    with TestClient(app) as client:
        html = client.get("/").text

    assert 'id="show-playbook-button"' in html
    assert 'id="show-sources-button"' in html
    assert 'id="run-scan-button"' in html
    assert 'id="scan-profile"' in html
    assert 'data-nav-target="dashboard"' in html
    assert 'data-section="findings"' in html
    assert 'id="upload-form"' in html


def test_scanner_endpoints_launch_run_and_return_findings():
    with TestClient(app) as client:
        profiles = client.get("/api/scanner/profiles")
        modules = client.get("/api/scanner/modules")
        launched = client.post(
            "/api/scanner/run",
            json={
                "profile_name": "mock-local-lab",
                "mode": "dry-run",
                "selected_modules": ["json_injection", "api_auth_validation"],
            },
        )
        runs = client.get("/api/scanner/runs")

    assert profiles.status_code == 200
    assert len(profiles.json()["profiles"]) >= 1
    assert modules.status_code == 200
    assert len(modules.json()["modules"]) >= 1
    assert launched.status_code == 200
    assert launched.json()["run_summary"]["findings_count"] >= 2
    assert runs.status_code == 200
    assert len(runs.json()["runs"]) >= 1


def test_scanner_cli_lists_profiles_and_runs_dry_run():
    profiles = subprocess.run(
        [sys.executable, "scanner_cli.py", "profiles", "list"],
        cwd="D:\\5G-Project",
        capture_output=True,
        text=True,
        check=True,
    )
    scan = subprocess.run(
        [sys.executable, "scanner_cli.py", "run", "--profile", "mock-local-lab", "--mode", "dry-run"],
        cwd="D:\\5G-Project",
        capture_output=True,
        text=True,
        check=True,
    )

    assert "mock-local-lab" in profiles.stdout
    assert "run_summary" in scan.stdout


def test_classmate_style_cli_runs_scan_and_creates_report_files():
    scan = subprocess.run(
        [sys.executable, "main.py", "--mode", "scan", "--nf", "UDM"],
        cwd="D:\\5G-Project",
        capture_output=True,
        text=True,
        check=True,
    )

    assert "CHECK-004" in scan.stdout
    assert "VULNERABLE" in scan.stdout
    assert "report.json" in scan.stdout


def test_classmate_style_cli_runs_attack_mode():
    attack = subprocess.run(
        [sys.executable, "main.py", "--mode", "attack", "--module", "udm"],
        cwd="D:\\5G-Project",
        capture_output=True,
        text=True,
        check=True,
    )

    assert "ATTACK-002" in attack.stdout
    assert "SUCCESS" in attack.stdout
