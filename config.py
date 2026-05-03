from __future__ import annotations

from core.scanner_engine import load_target_profile

DEFAULT_PROFILE = load_target_profile("mock-local-lab")

NRF_HOST = "127.0.0.1"
NRF_PORT = 8000
NRF_URL = f"{DEFAULT_PROFILE.base_url}"

UDM_URL = f"{DEFAULT_PROFILE.base_url}/api/udm"
AMF_URL = f"{DEFAULT_PROFILE.base_url}/api/amf"
AUSF_URL = f"{DEFAULT_PROFILE.base_url}/api/ausf"
SMF_URL = f"{DEFAULT_PROFILE.base_url}/api/smf"
PCF_URL = f"{DEFAULT_PROFILE.base_url}/api/pcf"

ROGUE_NF_ID = "12345678-1234-1234-1234-123456789012"
ROGUE_NF_TYPE = "AMF"
ROGUE_NF_IP = "127.0.0.99"

TIMEOUT = int(DEFAULT_PROFILE.timeout_seconds)
SUPI_START = 1
SUPI_END = 20
