# Module 2 — Implementation Summary

**Wi-Fi / LAN Security Analyzer — Module 2: Security Analysis, SQLite Persistence, Inventory, Findings, and Reports**

---

## Overview

Module 2 extends the existing Module 1 scaffold (React + Vite + Tailwind frontend, FastAPI + Nmap backend) with a full persistence layer, device inventory, risk analysis engine, security scoring, scan history comparison, and CSV/print reports.

---

## New Files Created

### Backend

| File | Purpose |
|------|---------|
| `backend/app/database/db.py` | SQLite database layer — schema init, migrations, versioning, connection factory |
| `backend/app/services/inventory_service.py` | Device identity across scans; MAC-first with IP fallback; approval workflow |
| `backend/app/services/risk_engine.py` | Rule-based security finding engine (NEW_DEVICE, SENSITIVE_PORT, POLICY_PORT, INCOMPLETE_SCAN rules) |
| `backend/app/services/score_service.py` | Security score calculator (0–100, deductions per severity); persists `scan_scores` |
| `backend/app/services/report_service.py` | Report builder and CSV exporter with CSV-injection sanitization |
| `backend/app/api/devices.py` | REST endpoints for device inventory and approval workflow |
| `backend/app/api/findings.py` | REST endpoint to retrieve security findings for a scan |
| `backend/app/api/reports.py` | REST endpoints for JSON report and CSV download |
| `backend/app/schemas/device.py` | Pydantic schemas for device and approval request |
| `backend/app/schemas/findings.py` | Pydantic schema for security findings |
| `backend/app/schemas/report.py` | Pydantic schema for report summary |
| `backend/data/.gitkeep` | Placeholder so `backend/data/` is tracked without committing `analyzer.db` |
| `.gitignore` | Excludes `analyzer.db`, `__pycache__`, `.venv`, `node_modules`, `dist`, etc. |

### Frontend

| File | Purpose |
|------|---------|
| `frontend/src/pages/ScanHistory.jsx` | Scan history list with side-by-side comparison (new vs gone hosts/ports) |
| `frontend/src/pages/SecurityFindings.jsx` | Per-scan findings list with severity badges and recommendations |
| `frontend/src/pages/NetworkDevices.jsx` | Device inventory with approval/revoke workflow |
| `frontend/src/pages/Reports.jsx` | Report summary card with CSV download and print view trigger |

---

## Files Modified

### Backend

| File | Change |
|------|--------|
| `backend/app/services/nmap_service.py` | Added DB persistence calls — creates scan record on start, saves device/port observations, updates status on completion/failure, calls risk engine and score service |
| `backend/app/api/scans.py` | Added `GET /api/scans` (list all scans) and `GET /api/scans/{scan_id}` endpoints; `GET /api/devices` delegate |
| `backend/app/schemas/scan.py` | Extended scan response schemas with `scan_id`, `status`, `started_at`, `completed_at`, `host_count`, `warnings` |
| `backend/app/main.py` | Registered new routers (devices, findings, reports); added DB init on startup |
| `backend/tests/conftest.py` | Added in-memory SQLite fixture and test-client factory for all Module 2 tests |

### Frontend

| File | Change |
|------|--------|
| `frontend/src/App.jsx` | Added routes for ScanHistory, SecurityFindings, NetworkDevices, Reports pages |
| `frontend/src/services/api.js` | Added API helper functions for scans list, findings, devices, approval, reports, CSV export |
| `frontend/src/services/scanService.js` | Extended with `getScans()`, `getScanById()` calls |
| `frontend/src/pages/Dashboard.jsx` | Added security score card, recent findings panel, and links to new pages |

---

## New API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/scans` | List all scans (paginated, newest first) |
| `GET` | `/api/scans/{scan_id}` | Get scan detail including score and finding counts |
| `GET` | `/api/scans/{scan_id}/findings` | List security findings for a scan |
| `GET` | `/api/scans/compare?a={id}&b={id}` | Compare two scans — diff of hosts and open ports |
| `GET` | `/api/devices` | List all known devices with approval status |
| `PATCH` | `/api/devices/{device_id}/approval` | Set device approval status (approved / revoked) |
| `GET` | `/api/reports/{scan_id}` | JSON report for a scan |
| `GET` | `/api/reports/{scan_id}/csv` | CSV download of scan findings |

---

## Database Schema (SQLite)

Six tables, all with foreign-key enforcement enabled per connection:

- **scans** — scan lifecycle record (id, scope, type, status, timestamps, host_count, error, warnings)
- **devices** — device inventory (id, mac, hostname, first_seen, last_seen, approval_status)
- **device_observations** — per-scan host sighting with IP and host state
- **port_observations** — per-scan open port record (protocol, port, state, service, product/version)
- **security_findings** — risk engine output (rule_id, severity, title, explanation, evidence, recommendation)
- **scan_scores** — computed security score with explanation and scoring_version

Schema version tracked in `schema_versions` table; init is idempotent (`CREATE TABLE IF NOT EXISTS`).

---

## Test Counts

| Test File | Tests | Coverage |
|-----------|-------|---------|
| `test_health.py` | 4 | Health endpoint (Module 1) |
| `test_network.py` | 4 | Interface listing (Module 1) |
| `test_validation.py` | 9 | Input validation helpers (Module 1) |
| `test_scans.py` | 11 | Discovery and port scan endpoints |
| `test_database.py` | 4 | Schema init, idempotency, FK enforcement |
| `test_inventory.py` | 9 | Device identity, MAC normalization, approval |
| `test_risk_engine.py` | 11 | All risk rules (new device, sensitive ports, incomplete scan) |
| `test_score.py` | 9 | Score calculation, deductions, provisional flag, persistence |
| `test_reports.py` | 9 | Report build, CSV output, CSV-injection sanitization, endpoints |
| `test_comparison.py` | 3 | Scan comparison diff endpoint |
| **Total** | **80** | **All passing** |

Module 1 had 29 tests. Module 2 added 51 new tests.

---

## Security Score Logic

- Starts at 100.
- Per finding deductions: **High** −15, **Medium** −8, **Low** −3, **Info** 0.
- Score floors at 0.
- Marked **provisional** when the scan status is `partial` or `timed_out`.
- Scoring version is stored with each score record to support future recalculation.

---

## Risk Rules Implemented

| Rule ID | Severity | Trigger |
|---------|----------|---------|
| `NEW_DEVICE_001` | Medium | Device with `pending_review` approval status |
| `SENSITIVE_PORT_001` | High | Open port in sensitive list (23 Telnet, 21 FTP, 512–514 r-commands, 135/139/445 SMB, 1900 UPnP, 5900 VNC) |
| `POLICY_PORT_001` | Low | Open port in policy-review list (22 SSH, 80 HTTP, 3389 RDP, 5432/3306 DB ports) |
| `INCOMPLETE_SCAN_001` | Info | Scan status is `partial` or `timed_out` |

---

## Known Limitations

1. **Nmap availability** — discovery and port-scan tests mock the Nmap subprocess. On machines without Nmap installed, real scans return an error (expected behavior; no mock fallback in production path).
2. **MAC address reliability** — Nmap only returns MAC addresses for devices on the same Layer-2 segment. Devices on different subnets fall back to IP-based identity, meaning a device that changes IP will be treated as a new device.
3. **No authentication** — all API endpoints are unauthenticated. Suitable for a local college project; not production-ready.
4. **Single-user** — approval workflow has no user identity; any client can approve or revoke any device.
5. **No real-time scan streaming** — scan progress is not pushed to the frontend (polling or WebSocket not implemented). The frontend polls or waits for the response.
6. **CSV export is in-memory** — very large port scan results (thousands of rows) could use significant memory before streaming. Acceptable for LAN scale.
7. **Schema migrations** — current mechanism is `CREATE TABLE IF NOT EXISTS` (safe for additive changes). Column additions or renames would require a manual migration.

---

## Files That Should NOT Be Committed

- `backend/data/analyzer.db` — runtime database, excluded via `.gitignore`
- `backend/.venv/` and `backend/venv/` — virtual environments
- `frontend/node_modules/` and `frontend/dist/`
