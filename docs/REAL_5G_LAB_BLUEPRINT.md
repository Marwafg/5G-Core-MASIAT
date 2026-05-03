# Real 5G Lab Blueprint

## Objective

Build a practical testbed for auditing Service-Based Interfaces (SBI) in a 5G core and simulating injection attacks against NRF- and UDM-adjacent API flows.

## Recommended Lab Layout

- Host OS: Ubuntu 22.04 VM or dedicated Linux workstation
- Core option A: free5GC with Docker Compose
- Core option B: Open5GS on a single machine
- UE/RAN simulator: UERANSIM
- Security tooling: Burp Suite, 5GC API parse, 5Greplay, custom API test scripts
- This project: use the local dashboard and attack runner as the evidence and reporting layer

## Deployment Strategy

1. Start the open-source 5G core.
2. Register subscribers and slices.
3. Connect UERANSIM gNB and UE.
4. Put an API gateway or reverse proxy in front of exposed SBI services.
5. Replay benign and malicious API requests.
6. Compare vulnerable and secured outcomes in this tool.

## Injection Testing Focus

- SQL injection simulation on subscriber lookups
- NoSQL injection simulation on Mongo-backed discovery or subscriber APIs
- OS command injection simulation on diagnostic tooling
- Input validation, authentication, and gateway enforcement checks

## Success Evidence

- Attack payload accepted by vulnerable path
- Sensitive data over-returned or dangerous command plan shown
- Secure path rejects or safely contains the same payload
- Logs, metrics, and exported report captured in `/api/tester/report`
