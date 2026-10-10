# Implementation Plan — Module 2: Security Analysis, SQLite Database, Scan History and Reports

## Codebase Summary (confirmed by reading actual files)

- **Backend** is FastAPI + Python in `backend/app/`. Services in `services/`, API routes in `api/`, schemas in `schemas/`, and a stub DB in `database/db.py`.
- **`nmap_service.py`** owns two in-memory stores: `_scan_history` (list, max 50) and `_devices` (dict keyed by IP). Real scans persist nothing to disk.
- **`database/db.py`** is a stub — it only sets `DB_PATH = "backend/data/analyzer.db"`.
- **Backend tests** (13 tests in `test_scans.py`, 10 in `test_validation.py`, plus `test_health.py`, `test_network.py`) all pass. Tests mock `nmap.PortScanner` at `app.services.nmap_service.nmap.PortScanner`.
- **Frontend** React + Vite + Tailwind. `api.js` exports `get` and `post` (no `patch`). `scanService.js` exports `runDiscovery`, `runPortScan`, `getScanHistory`, `getDevices`.
- **Pages**: Dashboard (full), NetworkDevices (full), PortScanner (full), SecurityFindings (placeholder), ScanHistory (session-only), Reports (session-only with print stub).
- **No frontend test runner** is configured (no vitest/jest in package.json); frontend verification is `npm run build` succeeding.
- **Existing routes**: `POST /api/scans/discovery`, `POST /api/scans/ports`, `GET /api/scans`, `GET /api/devices`, `GET /api/health`, `GET /api/network/interfaces`.

---

## Implementation Plan

- [ ] 1. **Database layer** — implement `backend/app/database/db.py`
      Replace the stub with a full SQLite module: absolute `DB_PATH` resolved relative to this file so it always lands at `backend/data/analyzer.db` regardless of CWD; `get_connection()` that enables `PRAGMA foreign_keys = ON` and `row_factory = sqlite3.Row`; `init_db()` that creates all six tables plus a `schema_versions` table using `CREATE TABLE IF NOT EXISTS`; schema version tracking via `schema_versions` (`version INTEGER PRIMARY KEY, applied_at TEXT`); if version < 1 then apply migration 1 (all tables); repeated calls to `init_db()` are fully safe (idempotent). Table definitions exactly match the six entities from the requirements (scans, devices, device_observations, port_observations, security_findings, scan_scores). Use `WITH transaction`, parameterized queries throughout.

      **Key decisions:**
      - Use `pathlib.Path(__file__).resolve().parent.parent.parent.parent / "data" / "analyzer.db"` so the path is always correct regardless of where uvicorn is launched from.
      - Schema version 1 creates all tables in one migration; future modules add version 2, 3, etc.
      - `get_connection()` is a context manager via `contextlib.contextmanager` — `yield conn` then `conn.close()`.

      Files:
      - `backend/app/database/db.py` (rewrite the stub)
      - `backend/data/.gitkeep` (create this file so the data dir exists in git without committing the DB)

      Verify: `cd backend && python -c "from app.database.db import init_db; init_db(); print('OK')"` — prints OK without errors and creates `backend/data/analyzer.db`.

- [ ] 2. **Pydantic schemas** — extend `scan.py` and create new schema files
      Add to `backend/app/schemas/scan.py`: `ScanDetail` (full scan with `completed_at`, `error_message`, `limitations`, `host_count`, `score`), extend `ScanSummary` to include `completed_at` (optional). These additions must be additive — existing fields must remain.

      Create `backend/app/schemas/device.py`: `DeviceDB` (full device from DB: `device_id`, `mac_address`, `hostname`, `first_seen`, `last_seen`, `approval_status`, `created_at`, `updated_at`, `last_ip`), `ApprovalUpdateRequest` (body for PATCH with `approval_status: Literal["approved","revoked","pending_review"]`).

      Create `backend/app/schemas/findings.py`: `FindingOut` (all finding fields: `finding_id`, `scan_id`, `device_id`, `rule_id`, `title`, `severity`, `explanation`, `evidence`, `recommendation`, `created_at`).

      Create `backend/app/schemas/report.py`: `ReportOut` (wraps a scan with its devices, port observations, findings, and score into a single response object for the GET /api/reports/{scan_id} endpoint).

      Files:
      - `backend/app/schemas/scan.py` (extend)
      - `backend/app/schemas/device.py` (create)
      - `backend/app/schemas/findings.py` (create)
      - `backend/app/schemas/report.py` (create)

      Verify: `cd backend && python -c "from app.schemas.device import DeviceDB; from app.schemas.findings import FindingOut; from app.schemas.report import ReportOut; print('OK')"` — prints OK.

- [ ] 3. **Inventory service** — create `backend/app/services/inventory_service.py`
      Identity logic: if MAC address is present and not a broadcast/multicast/empty string, normalize it to uppercase with colons (`AA:BB:CC:11:22:33`) and use it as the stable key. If MAC is absent or unreliable, use IP address as the fallback key with a `ip:` prefix in a `device_key` field (stored as `mac_address = NULL`, `device_key = "ip:192.168.1.5"`). Never merge two devices that only share a hostname.

      `upsert_device(conn, ip, mac, hostname, scan_id) -> str (device_id)`:
      1. Compute the lookup key (MAC if present, else `ip:<ip>`).
      2. `SELECT device_id FROM devices WHERE mac_address = ?` (or WHERE mac_address IS NULL AND last_known_ip = ? for IP-fallback).
      3. If not found: INSERT new device with `approval_status = "pending_review"`, `first_seen = now`, `last_seen = now`.
      4. If found: UPDATE `last_seen`, `hostname` (if the new value is not None), `last_known_ip`.
      5. Return `device_id`.

      Add `last_known_ip TEXT` column to devices table (add to the schema in step 1 — note this for the implementer). This is needed for IP-fallback identity.

      `get_all_devices(conn) -> list[dict]`: SELECT all devices joined with their latest observed IP.
      `update_approval(conn, device_id, status) -> bool`: UPDATE devices SET approval_status WHERE device_id; return True if rowcount > 0.
      `get_device_by_id(conn, device_id) -> dict | None`.

      Files:
      - `backend/app/services/inventory_service.py` (create)
      - `backend/app/database/db.py` (ensure `last_known_ip TEXT` is in the devices table schema)

      Verify: `cd backend && python -c "from app.services.inventory_service import upsert_device, update_approval; print('OK')"` — prints OK.

- [ ] 4. **Risk engine** — create `backend/app/services/risk_engine.py`
      Implement exactly four rules. Each rule is a function that receives the scan data and returns a list of finding dicts (may be empty).

      **NEW_DEVICE_001** (`severity = "info"`): For each device observation in the scan, check if `approval_status == "pending_review"`. If so, emit a finding: "New device detected — not yet reviewed". Evidence = IP + MAC. Recommendation = "Review and approve the device in the inventory if it belongs to you."

      **SENSITIVE_PORT_001** (`severity = "high"`): Port observations in the scan with `state = "open"` and port in the sensitive list: `[21, 23, 2323, 3389, 5900, 5901, 69, 161, 162, 512, 513, 514]` (FTP, Telnet, RDP, VNC, TFTP, SNMP, rsh, rlogin, rexec). Emit one finding per device per sensitive port found.

      **POLICY_PORT_001** (`severity = "medium"`): Port observations in the scan with `state = "open"` and port in the policy list: `[22, 80, 3306, 5432, 6379, 27017, 1433, 8080, 8443]`. These are not automatically bad but warrant review. Emit one finding per device per policy port.

      **INCOMPLETE_SCAN_001** (`severity = "low"`): If `scan.status in ("partial", "timed_out", "timeout", "error")`, emit one finding for the scan. Evidence = `scan.error_message` or `scan.status`. Recommendation = "Re-run the scan with elevated privileges or a smaller target range."

      `run_risk_engine(conn, scan_id) -> list[dict]`: Load the scan record and its port observations from the DB, run all four rules, INSERT findings into `security_findings` with dedup key = `sha256(scan_id + device_id + rule_id + port_number)` using `INSERT OR IGNORE`. Return the list of inserted findings.

      Files:
      - `backend/app/services/risk_engine.py` (create)

      Verify: `cd backend && python -c "from app.services.risk_engine import run_risk_engine; print('OK')"` — prints OK.

- [ ] 5. **Score service** — create `backend/app/services/score_service.py`
      `calculate_score(findings: list[dict]) -> dict`:
      - Start at 100.
      - Deduct per finding by severity: `high` → -15, `medium` → -8, `low` → -3, `info` → 0.
      - Floor at 0, ceiling at 100.
      - Set `provisional = True` if the scan was incomplete (i.e., any INCOMPLETE_SCAN_001 finding exists in the list).
      - Return `{"score": int, "provisional": bool, "explanation": str, "scoring_version": 1}`.

      `save_score(conn, scan_id, score_dict) -> None`: INSERT into `scan_scores` (upsert: `INSERT OR REPLACE`).

      Files:
      - `backend/app/services/score_service.py` (create)

      Verify: `cd backend && python -c "from app.services.score_service import calculate_score; r = calculate_score([]); assert r['score'] == 100; print('OK')"` — prints OK.

- [ ] 6. **Modify `nmap_service.py`** — wire in DB persistence while keeping in-memory stores
      This is the most critical change. The in-memory `_scan_history` and `_devices` stores must continue to work exactly as before so the existing frontend (which reads from `GET /api/scans` and `GET /api/devices`) is not broken.

      Changes to `run_host_discovery(subnet)`:
      1. Before the scan: call `init_db()` (idempotent) and `get_connection()`, INSERT a scan record with `status = "running"`.
      2. For each discovered host: call `upsert_device(conn, ip, mac, hostname, scan_id)` → get `device_id`. INSERT a `device_observations` row.
      3. After success: UPDATE scan record to `status = "completed"`, set `completed_at`, `host_count`.
      4. Call `run_risk_engine(conn, scan_id)`, then `save_score(conn, scan_id, calculate_score(findings))`.
      5. On error: UPDATE scan record to the appropriate error status. Preserve partial observations.
      6. Keep all existing `_store_scan(...)` and `_devices[host_ip] = ...` calls **in place** — do not remove them.

      Changes to `run_port_scan(target_ip, ports)`:
      1. INSERT a scan record with `scan_type = "port_scan"`, `status = "running"`.
      2. Look up `device_id` for `target_ip` from devices table (may be None if device was never discovered).
      3. For each port result: INSERT a `port_observations` row.
      4. UPDATE scan record to `completed` or error.
      5. Call `run_risk_engine(conn, scan_id)`, then `save_score(...)`.
      6. Keep all existing `_store_scan(...)` calls in place.

      **Gotcha**: DB imports must be lazy or guarded so that tests that mock nmap but don't set up a DB still pass. Use `try/except` around DB calls and log warnings on failure — the scan result must still be returned even if DB persistence fails.

      Files:
      - `backend/app/services/nmap_service.py` (modify)

      Verify: `cd backend && python -m pytest tests/test_scans.py tests/test_validation.py -v` — all 23 existing tests still pass.

- [ ] 7. **New and extended API routes** — devices, scans, findings, reports; register in main.py
      **Extend `backend/app/api/devices.py`**:
      - `GET /api/devices` — now reads from DB (falls back to in-memory if DB unavailable). Returns list of `DeviceDB`.
      - `GET /api/devices/{device_id}` — returns a single `DeviceDB` or 404.
      - `PATCH /api/devices/{device_id}/approval` — accepts `ApprovalUpdateRequest`, updates approval_status, returns updated `DeviceDB`.

      **Extend `backend/app/api/scans.py`**:
      - Keep existing `POST /api/scans/discovery`, `POST /api/scans/ports`, `GET /api/scans` unchanged in signature.
      - Add `GET /api/scans/compare?scan_a={id}&scan_b={id}` — compares two scans by diffing device counts, port counts, and new/removed devices. **Must be registered BEFORE `GET /api/scans/{scan_id}`** to avoid route shadowing.
      - Add `GET /api/scans/{scan_id}` — returns full `ScanDetail` including devices, ports, findings, score.

      **Create `backend/app/api/findings.py`**:
      - `GET /api/findings?scan_id={optional}` — returns list of `FindingOut`, optionally filtered by scan_id.

      **Create `backend/app/api/reports.py`**:
      - `GET /api/reports/{scan_id}` — returns full `ReportOut` (scan + devices + ports + findings + score).
      - `GET /api/reports/{scan_id}/csv` — returns a `StreamingResponse` with `Content-Type: text/csv` and `Content-Disposition: attachment; filename=report_{scan_id[:8]}.csv`. **Formula injection protection**: any cell value starting with `=`, `+`, `-`, `@`, or TAB must be prefixed with a single quote.

      **Register in `backend/app/main.py`**:
      - Import and register `findings.router` and `reports.router` with `prefix="/api"`.
      - Add lifespan handler that calls `init_db()` on startup.

      **Gotcha on route ordering in `scans.py`**: FastAPI matches routes top-to-bottom. Register `/api/scans/compare` before `/api/scans/{scan_id}`, otherwise the literal `compare` is swallowed as a scan_id parameter.

      Files:
      - `backend/app/api/devices.py` (extend)
      - `backend/app/api/scans.py` (extend)
      - `backend/app/api/findings.py` (create)
      - `backend/app/api/reports.py` (create)
      - `backend/app/main.py` (add lifespan, register new routers)

      Verify: `cd backend && python -m pytest tests/ -v` — all existing tests pass. Then manually check: `cd backend && python -c "from app.main import app; print('OK')"` — imports without error.

- [ ] 8. **Report service** — create `backend/app/services/report_service.py`
      `build_report(conn, scan_id) -> dict`: assembles the full report dict from DB: scan record, devices via device_observations, port_observations, findings, score.

      `build_csv(report: dict) -> str`: generates CSV content as a string.
      - Header row: `scan_id, scan_type, target, started_at, completed_at, status, score, device_ip, device_mac, device_hostname, approval_status, port, protocol, state, service, severity, rule_id, title, recommendation`.
      - One row per (device, port, finding) combination; repeat scan/device fields per row.
      - **Formula injection protection**: wrap cell content in `_sanitize_csv_cell(value)` — if the string representation starts with `=`, `+`, `-`, `@`, `\t`, `\r`, prefix with `'`.
      - Return the full CSV string (the route handler writes it into a `StreamingResponse`).

      Files:
      - `backend/app/services/report_service.py` (create)

      Verify: `cd backend && python -c "from app.services.report_service import build_report, build_csv; print('OK')"` — prints OK.

- [ ] 9. **Backend tests** — add five new test files
      All new tests follow the same `conftest.py` pattern (async httpx client) and mock DB where needed.

      **`backend/tests/test_database.py`**:
      - Test `init_db()` is idempotent (call twice, no error, DB exists).
      - Test `get_connection()` returns a connection with FK enforcement on.
      - Test all six tables exist after init.
      - Test schema_versions has version 1 after init.
      Use a **temp DB** by monkeypatching `app.database.db.DB_PATH` to a `tmp_path` file (pytest's `tmp_path` fixture).

      **`backend/tests/test_inventory.py`**:
      - Test `upsert_device` creates a new device with `pending_review`.
      - Test `upsert_device` with the same MAC returns the same `device_id` and updates `last_seen`.
      - Test IP-fallback: two different IPs with no MAC create two separate devices.
      - Test `update_approval` changes status to `approved`.
      - All tests use `tmp_path` monkeypatch.

      **`backend/tests/test_risk_engine.py`**:
      - Test NEW_DEVICE_001 triggers for a pending_review device.
      - Test SENSITIVE_PORT_001 triggers for port 23 open.
      - Test POLICY_PORT_001 triggers for port 22 open.
      - Test INCOMPLETE_SCAN_001 triggers when scan status is "error".
      - Test that SENSITIVE_PORT_001 does NOT trigger for a closed port.
      - Use in-memory/tmp_path DB, insert records directly before calling `run_risk_engine`.

      **`backend/tests/test_score.py`**:
      - Test empty findings → score 100, provisional False.
      - Test one high finding → score 85.
      - Test many findings → floor at 0.
      - Test INCOMPLETE_SCAN_001 finding → provisional True.

      **`backend/tests/test_reports.py`**:
      - Test `build_csv` formula injection: a device hostname `=DANGEROUS` is sanitized to `'=DANGEROUS`.
      - Test `GET /api/reports/{scan_id}` returns 404 for unknown scan_id.
      - Test `GET /api/reports/{scan_id}/csv` returns Content-Type text/csv for a seeded scan.
      - Test `GET /api/findings` returns 200 and a list.

      **`backend/tests/test_comparison.py`**:
      - Test `GET /api/scans/compare?scan_a=X&scan_b=Y` returns 404 when either scan is not found.
      - Test `GET /api/scans/compare` returns a diff dict with `new_devices`, `removed_devices`, `port_changes` keys when both scans exist and are seeded in a tmp DB.

      Files:
      - `backend/tests/test_database.py` (create)
      - `backend/tests/test_inventory.py` (create)
      - `backend/tests/test_risk_engine.py` (create)
      - `backend/tests/test_score.py` (create)
      - `backend/tests/test_reports.py` (create)
      - `backend/tests/test_comparison.py` (create)
      - `backend/tests/conftest.py` (extend: add `tmp_db` fixture that monkeypatches DB_PATH and calls `init_db()`)

      Verify: `cd backend && python -m pytest tests/ -v` — all tests pass (existing 23 + new tests).

- [ ] 10. **Frontend services** — extend `api.js` and `scanService.js`
       Add `patch(path, body)` to `frontend/src/services/api.js` following the same pattern as `post`.

       Add to `frontend/src/services/scanService.js`:
       - `getScanById(scanId)` → `get('/api/scans/' + scanId)`
       - `compareScans(scanA, scanB)` → `get('/api/scans/compare?scan_a=' + scanA + '&scan_b=' + scanB)`
       - `getFindings(scanId)` → `get('/api/findings' + (scanId ? '?scan_id=' + scanId : ''))`
       - `getReport(scanId)` → `get('/api/reports/' + scanId)`
       - `getDeviceById(deviceId)` → `get('/api/devices/' + deviceId)`
       - `updateApproval(deviceId, status)` → `patch('/api/devices/' + deviceId + '/approval', { approval_status: status })`
       - `getReportCsvUrl(scanId)` → returns the string URL (no fetch; used for `window.location.href = ...` download)

       Files:
       - `frontend/src/services/api.js` (extend)
       - `frontend/src/services/scanService.js` (extend)

       Verify: `cd frontend && npm run build` — builds without errors.

- [ ] 11. **Frontend pages** — extend five pages
       **Dashboard.jsx**: Add a "Security Score" stat card (fourth card, replaces or sits alongside existing fourth card). After a scan completes, fetch the score from the returned `scan_id` via `getReport(scan_id)` and display `score/100` in the stat card. Keep all existing stat cards; add the score one.

       **NetworkDevices.jsx**: 
       - Change data source to use `DeviceDB` shape (add `device_id`, `approval_status`, `first_seen` columns from DB endpoint).
       - Add "Approval" column showing a `Badge` (green=approved, yellow=pending_review, red=revoked).
       - Add approve/revoke action buttons in the Actions column. On click, call `updateApproval(device_id, newStatus)` and refetch.
       - Preserve existing "Scan Ports" button behavior.
       - Keep backward compat: if `device_id` is undefined (in-memory fallback), hide approval buttons gracefully.

       **SecurityFindings.jsx**: 
       - Remove the placeholder content.
       - On mount, fetch all findings via `getFindings()`.
       - Show a table with columns: Severity (Badge: red=high, yellow=medium, blue=low, gray=info), Rule, Title, Device IP, Recommendation.
       - Add a scan_id filter dropdown (populated from `getScanHistory()`).
       - Show a summary count by severity at the top.

       **ScanHistory.jsx**: 
       - Remove the "session-only" banner.
       - Extend `ScanSummary` display to show `completed_at`.
       - Add a "Compare" feature: two checkboxes per row; when two scans are checked, show a "Compare Selected" button that calls `compareScans` and displays the diff in a Card below the table.
       - Keep existing refetch button.

       **Reports.jsx**: 
       - Remove the "Module 2 coming soon" note.
       - Add a scan selector dropdown (from `getScanHistory()`).
       - When a scan is selected, call `getReport(scan_id)` and display: scan info, score badge, device table, findings table.
       - Add "Download CSV" button that sets `window.location.href = getReportCsvUrl(scan_id)`.
       - Keep the existing print button.

       **MainLayout.jsx**: Update version footer from "Module 1 — v1.0.0" to "Module 2 — v2.0.0".

       Files:
       - `frontend/src/pages/Dashboard.jsx` (extend)
       - `frontend/src/pages/NetworkDevices.jsx` (extend)
       - `frontend/src/pages/SecurityFindings.jsx` (replace placeholder)
       - `frontend/src/pages/ScanHistory.jsx` (extend)
       - `frontend/src/pages/Reports.jsx` (extend)
       - `frontend/src/layouts/MainLayout.jsx` (update version)

       Verify: `cd frontend && npm run build` — builds without errors or type warnings.

- [ ] 12. **Frontend build verification**
       Run the production build and confirm it succeeds with no errors. This is the only frontend verification available since no test runner is configured.

       Files: none (verification only)

       Verify: `cd frontend && npm run build` — exits 0, `dist/` directory is populated.

- [ ] 13. **requirements.txt** — confirm no new packages needed
       `sqlite3` is in Python's standard library. All other needed packages (`uuid`, `hashlib`, `csv`, `io`, `contextlib`) are also standard library. No new pip packages are required.

       Files:
       - `backend/requirements.txt` — add a comment line `# sqlite3, hashlib, csv, io, contextlib are stdlib — no extra install needed` at the top. No version changes.

       Verify: `cd backend && pip install -r requirements.txt` — installs without error.

- [ ] 14. **README.md** — add Module 2 documentation
       Extend `README.md` (the root one at `wifi-lan-security-analyzer/README.md`):
       - Update the project overview table to show Module 2 features as implemented (not "coming next").
       - Add a "Module 2 — Security Analysis Engine" section documenting: SQLite DB location, approval workflow, security rules (four rules with IDs), scoring formula, scan comparison, CSV export, new API endpoints (`GET /api/scans/{id}`, `GET /api/scans/compare`, `GET /api/devices/{id}`, `PATCH /api/devices/{id}/approval`, `GET /api/findings`, `GET /api/reports/{id}`, `GET /api/reports/{id}/csv`).
       - Update folder structure to include new files.
       - Keep all existing Module 1 documentation.

       Files:
       - `README.md` (extend)

       Verify: `cd backend && python -m pytest tests/ -v` — all tests still pass (final regression check).

---

## Key Decisions

| Decision | Rationale |
|---|---|
| Keep `_scan_history` and `_devices` in-memory stores | Existing frontend reads `GET /api/scans` and `GET /api/devices`, which return from these stores. Removing them would break the frontend. DB persistence is additive. |
| DB calls wrapped in try/except in nmap_service.py | Tests mock nmap but do not set up a DB. Guarding DB calls means all 23 existing tests pass without change. |
| `/api/scans/compare` registered before `/api/scans/{scan_id}` | FastAPI routes match first-registered first. "compare" as a literal path must come before the parameterized `{scan_id}`. |
| MAC-based identity with IP fallback (not hostname) | MACs are stable across IP reassignment. Hostnames can collide. IP alone changes. The IP fallback with `ip:` prefix prevents false merges. |
| `INSERT OR IGNORE` for findings dedup | Re-running a scan should not duplicate findings. The SHA-256 key on (scan_id, device_id, rule_id, port) is stable. |
| `csv` module from stdlib for CSV generation | No new dependency. Formula injection protection applied at cell-write time. |
| No vitest/jest added | The project has no frontend test framework. Adding one is out of scope and would require config changes the task doesn't request. Build success is the verification proxy. |
| `init_db()` called in FastAPI lifespan | Ensures DB is ready before any request is served, on every restart. Idempotent so safe to call repeatedly. |
