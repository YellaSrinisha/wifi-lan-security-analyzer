# Wi-Fi / LAN Security Analyzer

A local network security tool that discovers devices on your subnet, fingerprints open ports, and surfaces potential security findings — all through a fast React/Vite dashboard backed by a FastAPI service.

> **Ethical use only.** Only scan networks you own or have explicit written permission to test. See [Security & Legal](#security--legal) below.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Folder Structure](#folder-structure)
4. [Prerequisites](#prerequisites)
5. [Setup — Windows PowerShell](#setup--windows-powershell)
6. [URLs](#urls)
7. [How to Use the App](#how-to-use-the-app)
8. [Running Backend Tests](#running-backend-tests)
9. [Frontend Production Build](#frontend-production-build)
10. [Troubleshooting](#troubleshooting)
11. [Security & Legal](#security--legal)
12. [Module 2 — Security Analysis Engine](#module-2--security-analysis-engine-implemented)

---

## Project Overview

### Module 1 — Network Discovery & Port Scanning (current)

| Capability | Detail |
|---|---|
| Host discovery | ICMP/ARP ping sweep across a CIDR subnet via Nmap |
| Device inventory | IP, MAC address, hostname, OS guess, open ports |
| Port scanning | Top-1000 or custom TCP port list, service/version detection |
| Scan history | In-memory log of every scan run during the session; data is now also persisted to SQLite |
| REST API | FastAPI with automatic OpenAPI docs at `/docs` |
| Dashboard | React/Vite SPA with Tailwind CSS |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Browser                              │
│                   http://localhost:5173                      │
└────────────────────────┬────────────────────────────────────┘
                         │  HTTP / JSON  (Vite dev proxy)
┌────────────────────────▼────────────────────────────────────┐
│              React 18 + Vite 5  (port 5173)                 │
│  pages/  components/  hooks/  services/  layouts/           │
└────────────────────────┬────────────────────────────────────┘
                         │  fetch → http://localhost:8000
┌────────────────────────▼────────────────────────────────────┐
│              FastAPI + Uvicorn  (port 8000)                  │
│  app/main.py  →  api/  →  services/  →  schemas/            │
└─────────────┬───────────────────────┬───────────────────────┘
              │                       │
┌─────────────▼──────────┐  ┌─────────▼──────────────────────┐
│   psutil 6.0           │  │   python-nmap 0.7.1            │
│   (interface/host      │  │   (Python wrapper)             │
│    enumeration)        │  └─────────┬──────────────────────┘
└────────────────────────┘            │  subprocess (no shell=True)
                               ┌──────▼──────────────────────┐
                               │   Nmap 7.99 binary          │
                               │   + Npcap 1.88 (Windows)    │
                               └─────────────────────────────┘
```

---

## Folder Structure

```
wifi-lan-security-analyzer/
├── README.md
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                  # FastAPI app, CORS, router registration, lifespan/init_db
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   ├── devices.py           # GET /api/devices, POST /api/devices/scan, GET/PATCH per device
│   │   │   ├── findings.py          # GET /api/findings
│   │   │   ├── health.py            # GET /api/health
│   │   │   ├── network.py           # GET /api/network/interfaces
│   │   │   ├── reports.py           # GET /api/reports/{scan_id}, GET /api/reports/{scan_id}/csv
│   │   │   └── scans.py             # GET/POST /api/scans, GET /api/scans/compare, GET /api/scans/{scan_id}
│   │   ├── database/
│   │   │   ├── __init__.py
│   │   │   └── db.py                # SQLite connection, init_db(), schema_versions table
│   │   ├── schemas/
│   │   │   ├── __init__.py
│   │   │   ├── device.py            # DeviceDB, ApprovalUpdateRequest
│   │   │   ├── findings.py          # FindingOut
│   │   │   ├── network.py           # Pydantic models for network data
│   │   │   ├── report.py            # ReportOut
│   │   │   └── scan.py              # ScanSummary, ScanDetail, and supporting models
│   │   └── services/
│   │       ├── __init__.py
│   │       ├── inventory_service.py # Device identity and upsert logic
│   │       ├── network_service.py   # Host discovery, interface enumeration
│   │       ├── nmap_service.py      # Port scanning via python-nmap; persists to DB
│   │       ├── report_service.py    # build_report(), build_csv()
│   │       ├── risk_engine.py       # run_risk_engine() — four security rules
│   │       └── score_service.py     # calculate_score(), save_score()
│   ├── data/                        # Runtime SQLite DB (backend/data/analyzer.db); not committed
│   │   └── .gitkeep
│   ├── tests/
│   │   ├── __init__.py
│   │   ├── conftest.py
│   │   ├── test_comparison.py
│   │   ├── test_database.py
│   │   ├── test_health.py
│   │   ├── test_inventory.py
│   │   ├── test_network.py
│   │   ├── test_reports.py
│   │   ├── test_risk_engine.py
│   │   ├── test_scans.py
│   │   ├── test_score.py
│   │   └── test_validation.py
│   ├── pytest.ini
│   └── requirements.txt
└── frontend/
    ├── index.html
    ├── package.json
    ├── vite.config.js
    ├── tailwind.config.js
    ├── postcss.config.js
    ├── eslint.config.js
    ├── public/
    ├── dist/                        # Generated by `npm run build`
    └── src/
        ├── main.jsx
        ├── App.jsx
        ├── index.css
        ├── assets/
        ├── components/
        │   ├── Badge.jsx
        │   ├── Button.jsx
        │   ├── Card.jsx
        │   ├── ErrorMessage.jsx
        │   ├── LoadingSpinner.jsx
        │   ├── PageHeader.jsx
        │   └── Table.jsx
        ├── hooks/
        │   ├── useDevices.js
        │   └── useScans.js
        ├── layouts/
        │   └── MainLayout.jsx
        ├── pages/
        │   ├── Dashboard.jsx
        │   ├── NetworkDevices.jsx
        │   ├── PortScanner.jsx
        │   ├── Reports.jsx
        │   ├── ScanHistory.jsx
        │   └── SecurityFindings.jsx
        ├── services/
        │   ├── api.js
        │   ├── networkService.js
        │   └── scanService.js
        └── types/
```

---

## Prerequisites

| Requirement | Version | Why it is needed |
|---|---|---|
| Python | 3.12 | Runtime for FastAPI, psutil, python-nmap |
| Node.js | 24 LTS | Runs the Vite dev server and builds the React frontend |
| npm | bundled with Node 24 | Installs frontend dependencies |
| Nmap | 7.99 | Binary called by python-nmap for all network scans |
| Npcap | 1.88 (Windows only) | WinPcap-compatible packet capture driver; required by Nmap for raw-socket scans on Windows |

**Download links**

- Python 3.12: https://www.python.org/downloads/
- Node.js 24 LTS: https://nodejs.org/
- Nmap 7.99: https://nmap.org/download.html (choose the Windows self-installer)
- Npcap 1.88: https://npcap.com/#download (install with "WinPcap API-compatible mode" checked)

---

## Setup — Windows PowerShell

### 1. Check execution policy

PowerShell may block venv activation scripts. Run once per machine:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

### 2. Backend

```powershell
# Navigate to the backend directory
cd "c:\WiFi security analyzer\wifi-lan-security-analyzer\backend"

# Create a virtual environment
python -m venv .venv

# Activate it
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

Start the API server (venv active):

```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Or without activating the venv first (run from the project root or any directory):

```powershell
cd "c:\WiFi security analyzer\wifi-lan-security-analyzer\backend"
..\..\wifi-lan-security-analyzer\backend\.venv\Scripts\uvicorn.exe app.main:app --reload --host 127.0.0.1 --port 8000
```

### 3. Frontend

Open a **second** PowerShell window:

```powershell
cd "c:\WiFi security analyzer\wifi-lan-security-analyzer\frontend"

# Install Node dependencies (first time only)
npm install

# Start the Vite dev server
npm run dev
```

Both processes must remain running while you use the app.

---

## URLs

| Service | URL |
|---|---|
| Frontend (Vite dev server) | http://localhost:5173 |
| Backend REST API | http://localhost:8000 |
| Interactive API docs (Swagger UI) | http://localhost:8000/docs |
| OpenAPI schema (ReDoc) | http://localhost:8000/redoc |

---

## How to Use the App

### Step 1 — Discover devices on your network

1. Open **http://localhost:5173** in your browser.
2. Navigate to **Dashboard**.
3. Click **Start Discovery Scan**.
4. Enter your subnet in CIDR notation, for example `192.168.1.0/24`.
5. Click **Scan**. Nmap performs a host discovery sweep; results populate the device list.

> Tip: to find your subnet, run `ipconfig` in PowerShell and look at your adapter's IPv4 address and subnet mask.

### Step 2 — Scan ports on a discovered device

1. Navigate to **Network Devices**.
2. The table shows every host found in the last discovery scan.
3. Click **Scan Ports** on any row to run a port scan against that specific IP.

### Step 3 — Manual port scan

1. Navigate to **Port Scanner**.
2. Enter a target IP address.
3. Select which ports or port range to scan.
4. Click **Scan**. Results show service names, port states, and version banners where detected.

### Other pages

| Page | Purpose |
|---|---|
| Scan History | Log of every scan run this session, loaded from persistent SQLite storage |
| Security Findings | Findings generated by the risk engine after each scan |
| Reports | Full per-scan report with CSV export |

---

## Running Backend Tests

Make sure the venv is active, then run from inside `backend/`:

```powershell
cd "c:\WiFi security analyzer\wifi-lan-security-analyzer\backend"
.\.venv\Scripts\Activate.ps1
python -m pytest tests/ -v
```

The test suite uses `httpx` and `pytest-asyncio` to exercise the FastAPI routes without needing a live Nmap binary.

---

## Frontend Production Build

From inside `frontend/`:

```powershell
cd "c:\WiFi security analyzer\wifi-lan-security-analyzer\frontend"
npm run build
```

Output lands in `frontend/dist/`. Serve it with any static host or point Uvicorn's `StaticFiles` mount at it.

---

## Troubleshooting

**Nmap not found**

python-nmap cannot locate the `nmap` executable. Add Nmap to your `PATH`:

1. Default install path: `C:\Program Files (x86)\Nmap`
2. Open *System Properties → Environment Variables → Path* and add that directory.
3. Restart your PowerShell session and verify with `nmap --version`.

**Permission errors / raw socket access**

Some scan types (SYN scan `-sS`) require elevated privileges. Right-click PowerShell and choose **Run as Administrator**, then restart the backend from that session.

**PowerShell execution policy blocks venv activation**

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

**CORS errors in the browser console**

The backend must be running on port 8000 and the frontend on port 5173. The FastAPI app allows both origins by default. Check that neither process exited.

**Port conflicts**

If 8000 or 5173 are already in use:

- Change the backend port: `uvicorn app.main:app --reload --host 127.0.0.1 --port 8001`
- Then update `VITE_API_BASE_URL` in `frontend/.env` to match: `VITE_API_BASE_URL=http://localhost:8001`

**Empty scan results**

- Check that your host firewall allows ICMP (ping) outbound.
- Some Wi-Fi access points enable **client isolation**, which prevents devices from seeing each other. Disable it on your router for local scanning.
- Verify the target device is powered on and connected to the same subnet.

**python-nmap cannot find the nmap binary even after PATH update**

Confirm the binary is visible in the same terminal session where Uvicorn is running:

```powershell
nmap --version
```

If it works there, restart Uvicorn in the same window. If not, revisit the PATH configuration and open a fresh PowerShell.

---

## Security & Legal

- **Only scan networks you own or have explicit written permission to test.** Unauthorized port scanning is illegal in many jurisdictions.
- Do not target public IP addresses, cloud hosts, or infrastructure you do not control.
- This tool does not include exploitation, brute-force, or credential-stuffing capabilities and must not be modified to add them.
- Scan results and device history are persisted in `backend/data/analyzer.db`. This file is excluded from source control.
- User-supplied input (IP addresses, subnets, port lists) is validated with Pydantic before being passed to Nmap. `shell=True` is never used when invoking external processes.

---

## Module 2 — Security Analysis Engine (implemented)

### Database

- **Location:** `backend/data/analyzer.db` (created automatically on first backend startup; not committed to source control)
- **Schema versioning:** a `schema_versions` table tracks applied migrations; `init_db()` is idempotent and safe to call on every restart
- **Entity tables:**
  - `schema_versions`
  - `scans`
  - `devices`
  - `device_observations`
  - `port_observations`
  - `security_findings`
  - `scan_scores`

### Approval Workflow

Every device discovered for the first time is placed in `pending_review` state. The three explicit states are:

| State | Meaning |
|---|---|
| `pending_review` | Device has been seen but not yet verified by the user |
| `approved` | User has confirmed the device is expected on the network |
| `revoked` | Device was previously approved but approval has been withdrawn |

To change a device's state, navigate to the **Network Devices** page and use the approval controls on the device row.

### Security Rules

The risk engine runs four rules automatically after every scan:

| Rule ID | Severity | Trigger |
|---|---|---|
| `NEW_DEVICE_001` | info | A device observation exists for a device whose `approval_status` is `pending_review` |
| `SENSITIVE_PORT_001` | high | An open port matches a list of high-risk services (FTP 21, Telnet 23/2323, TFTP 69, SNMP 161/162, rsh 512-514, RDP 3389, VNC 5900/5901) |
| `POLICY_PORT_001` | medium | An open port matches a list of commonly scrutinised services (SSH 22, HTTP 80, MySQL 3306, PostgreSQL 5432, Redis 6379, MongoDB 27017, MSSQL 1433, HTTP-alt 8080/8443) |
| `INCOMPLETE_SCAN_001` | low | The scan finished with status `partial`, `timed_out`, `timeout`, or `error` — findings may be incomplete |

### Scoring

The security score starts at **100** and deductions are applied per finding:

| Severity | Deduction per finding |
|---|---|
| high | −15 |
| medium | −8 |
| low | −3 |
| info | 0 |

The score is clamped to the range **0 – 100**. If an `INCOMPLETE_SCAN_001` finding is present, the score is marked **provisional** to indicate results may be partial.

### New API Endpoints (Module 2)

| Method | Path | Description |
|---|---|---|
| GET | `/api/scans/{scan_id}` | Full scan detail including score |
| GET | `/api/scans/compare` | Compare two scans (`?scan_a=<id>&scan_b=<id>`); returns added/removed devices and opened/closed ports |
| GET | `/api/devices/{device_id}` | Single device record from the inventory |
| PATCH | `/api/devices/{device_id}/approval` | Update approval status (`approved`, `revoked`, `pending_review`) |
| GET | `/api/findings` | List security findings; optionally filter by `?scan_id=<id>` |
| GET | `/api/reports/{scan_id}` | Full JSON report: scan, devices, ports, findings, score |
| GET | `/api/reports/{scan_id}/csv` | Download the same report as a CSV file |
