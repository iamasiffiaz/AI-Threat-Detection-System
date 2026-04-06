# AI Threat Detection System

> **Production-ready Security Operations Center (SOC) platform** with ML-powered anomaly detection, SIEM-style rule engine, LLM threat explanation, automated incident response, threat intelligence, and real-time dashboards.

---

## Architecture Overview

```
┌────────────────────────────────────────────────────────────────────────────┐
│                        AI Threat Detection System                          │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌─────────────┐      ┌──────────────────────────────────────────────┐   │
│   │   React UI  │─────▶│              FastAPI Backend                  │   │
│   │  (Vite/TS)  │◀─────│                                              │   │
│   │  Port 3000  │  WS  │  Routers: auth, logs, alerts, anomalies,    │   │
│   └─────────────┘      │  dashboard, incidents, intelligence,         │   │
│                         │  investigation, soar, soc-assistant,         │   │
│                         │  event-viewer, websocket                     │   │
│                         │                                              │   │
│                         │  Services: LogService, AlertService,         │   │
│                         │  RuleEngine, LLMService, CorrelationEngine,  │   │
│                         │  ThreatIntelService, SOARService,            │   │
│                         │  RiskScoringService, BehavioralProfileSvc,   │   │
│                         │  ClassificationService, CacheService,        │   │
│                         │  EventViewerService                          │   │
│                         │                                              │   │
│                         │  ML Engine: IsolationForest + LOF,           │   │
│                         │  FeatureEngineering, ModelManager (async)    │   │
│                         └──────────────────────────────────────────────┘   │
│                                    │                   │                    │
│              ┌─────────────────────┘                   │                    │
│              ▼                                         ▼                    │
│   ┌──────────────────┐                   ┌──────────────────┐              │
│   │   PostgreSQL 16  │                   │   Ollama LLM     │              │
│   │  (Async SQLAlch) │                   │  (Llama3/Gemma)  │              │
│   └──────────────────┘                   └──────────────────┘              │
│              │                                                              │
│              ▼                                                              │
│   ┌──────────────────┐                                                     │
│   │      Redis       │                                                     │
│   │  (Cache/Stream/  │                                                     │
│   │   Correlation)   │                                                     │
│   └──────────────────┘                                                     │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## Tech Stack

| Layer         | Technology                           |
|---------------|--------------------------------------|
| Backend       | FastAPI (Python 3.12), async/await   |
| Frontend      | React 18 + Vite + TypeScript         |
| Database      | PostgreSQL 16 (via asyncpg)          |
| ORM           | SQLAlchemy 2.0 (async)               |
| Cache         | Redis 7                              |
| ML/AI         | Scikit-learn (IsolationForest + LOF) |
| LLM           | Ollama (Llama3 / Gemma)              |
| Charts        | Recharts                             |
| Styling       | TailwindCSS + dark mode              |
| Auth          | JWT (HS256) + bcrypt                 |
| State         | Zustand + TanStack Query             |
| Containers    | Docker + Docker Compose              |

---

## Features

### Log Ingestion
- **File upload**: CSV, JSON, syslog, and newline-delimited JSON
- **API streaming**: `POST /api/v1/logs/stream` for real-time ingestion
- **Bulk ingestion**: `POST /api/v1/logs/bulk` for high-throughput batches
- Automatic field normalization from various log formats

### ML Anomaly Detection
- **Ensemble model**: Isolation Forest + Local Outlier Factor
- **Optional PyOD**: install `pyod` for additional models
- Feature engineering: IP behavior, port patterns, traffic volume, time features
- Anomaly scores normalized to [0, 1]; alerts triggered above configurable threshold
- Async training (non-blocking), model persistence to disk

### Rule Engine (SIEM-style)
| Rule | Trigger |
|------|---------|
| `brute_force_login` | 5+ failed logins from same IP in 10 min |
| `port_scan` | 20+ unique ports from same IP in 10 min |
| `ddos_flood` | 200+ requests/minute from single IP |
| `suspicious_port_access` | Connection to backdoor ports (4444, 1337, etc.) |
| `privilege_escalation` | Privilege escalation event types |
| `data_exfiltration` | Outbound transfer > 50MB |
| `critical_severity_event` | Any CRITICAL severity log |

### AI Threat Explanation
- Integrates with local **Ollama** LLM (Llama3, Gemma, etc.)
- Generates: threat explanation, attack type, MITRE ATT&CK TTPs, mitigation steps
- **Graceful fallback**: rule-based analysis when Ollama is offline

### AI SOC Assistant
- **Chat-style natural language interface** for analysts — ask questions about any alert or incident
- Context-aware: pulls live alert data, incident details, and log history from the database before answering
- Dedicated endpoints: explain alert, advise on remediation, summarize incident
- **Streaming responses** (SSE) for low-latency interactive experience
- Powered by the same local Ollama LLM with graceful fallback

### Incident Management
- **Automated incident creation** via the Correlation Engine — no manual grouping needed
- Correlation strategies:
  - `SAME_IP_BURST` — 3+ alerts from same IP within 5 minutes
  - `MULTI_RULE_CHAIN` — 2+ different rule types from same IP within 15 min
  - `MULTI_USER_TARGETING` — same IP hitting multiple users within 10 min
  - `HIGH_RISK_SINGLE` — single alert with risk score ≥ 85
- Full incident lifecycle: `open → investigating → contained → resolved → closed`
- Alert timeline view per incident
- Escalation workflow with severity promotion
- Incident summary statistics

### Threat Intelligence
- **GeoIP enrichment** via ip-api.com (country, city, ISP, org, ASN)
- **IP reputation scoring** via AbuseIPDB (optional API key)
- **Internal known-bad dataset**: CISA KEV ranges, Tor exit nodes, common scanners
- Two-tier cache: Redis (1-hour TTL) → PostgreSQL (long-term history)
- Bulk IP lookup endpoint
- Top-threats leaderboard

### IP Investigation & Forensics
- **Forensic report per IP**: full behavioral summary, risk score, threat intel, correlated alerts
- Recent log history for any IP
- Per-IP behavioral profiling (request patterns, port diversity, failure rates)
- Alert history for any IP
- Alert-level deep-dive investigation

### SOAR (Security Orchestration, Automation & Response)
- **IP blacklisting** with reason, expiry, and hit counter
- Redis hot-set for O(1) block checks at ingestion time — malicious IPs are blocked before processing
- **Automated playbooks** for each attack type with step-by-step response actions
- One-click automated response on any alert: runs the matching playbook and (optionally) blocks the source IP
- Playbook library covers: Brute Force, Port Scan, DDoS, Data Exfiltration, Privilege Escalation, Suspicious Port Access
- SOAR statistics: blocked IPs, total block hits, active playbooks

### Risk Scoring
- Dynamic **composite risk score** (0–100) per alert, combining:
  - Rule-based severity weight
  - ML anomaly score
  - Threat intelligence reputation
  - Behavioral profile signals
- Automatic severity reclassification based on final score

### Event Viewer
- **Windows Event Log-style live viewer** — monitors raw Redis streams and log channels
- Start/stop real-time monitoring, pull-now on demand
- Channel status inspection and watermark management
- Diagnostic endpoint for troubleshooting ingestion pipelines

### Dashboard
- Real-time KPIs: total logs, open alerts, anomalies, events/hour
- Charts: traffic timeline, severity distribution, top IPs, anomaly trends
- WebSocket-powered live alert notifications
- Alert management with status updates and AI analysis on-demand

### Security
- JWT Bearer authentication (access + refresh tokens)
- Role-based access: Admin (full control) / Analyst (read + analyze)
- bcrypt password hashing
- CORS, GZip middleware
- Non-root Docker containers

---

## Project Structure

```
AI Threat Detection System/
├── backend/
│   ├── app/
│   │   ├── main.py                        # FastAPI app, middleware, lifespan
│   │   ├── core/
│   │   │   ├── config.py                  # Pydantic settings from .env
│   │   │   ├── database.py                # Async SQLAlchemy engine + sessions
│   │   │   ├── db_migrations.py           # Runtime schema migrations
│   │   │   ├── security.py                # JWT + bcrypt
│   │   │   └── dependencies.py            # FastAPI dependency injection
│   │   ├── models/                        # SQLAlchemy ORM models
│   │   │   ├── user.py
│   │   │   ├── log_entry.py
│   │   │   ├── alert.py
│   │   │   ├── anomaly.py
│   │   │   ├── incident.py                # Incident model
│   │   │   ├── threat_intel.py            # Threat intel cache model
│   │   │   └── blacklist.py               # IP blacklist model
│   │   ├── schemas/                       # Pydantic validation schemas
│   │   ├── routers/                       # FastAPI route handlers
│   │   │   ├── auth.py
│   │   │   ├── logs.py
│   │   │   ├── alerts.py
│   │   │   ├── anomalies.py
│   │   │   ├── dashboard.py
│   │   │   ├── incidents.py               # Incident management
│   │   │   ├── intelligence.py            # Threat intelligence
│   │   │   ├── investigation.py           # IP forensics
│   │   │   ├── soar.py                    # SOAR & IP blacklist
│   │   │   ├── soc_assistant.py           # AI SOC chat assistant
│   │   │   ├── event_viewer.py            # Live event viewer
│   │   │   └── websocket.py
│   │   ├── services/                      # Business logic layer
│   │   │   ├── log_service.py             # Ingestion, parsing, bulk ops
│   │   │   ├── alert_service.py           # Alert CRUD + WebSocket broadcast
│   │   │   ├── rule_engine.py             # SIEM-style detection rules
│   │   │   ├── llm_service.py             # Ollama LLM integration
│   │   │   ├── correlation_service.py     # Alert → Incident correlation
│   │   │   ├── threat_intel_service.py    # GeoIP + IP reputation
│   │   │   ├── soar_service.py            # Playbooks + IP blocking
│   │   │   ├── risk_scoring_service.py    # Composite risk scoring
│   │   │   ├── behavioral_profile_service.py  # Per-IP behavior analysis
│   │   │   ├── classification_service.py  # Attack type classification
│   │   │   ├── cache_service.py           # Redis cache abstraction
│   │   │   └── event_viewer_service.py    # Real-time event streaming
│   │   ├── ml/                            # ML/AI components
│   │   │   ├── feature_engineering.py
│   │   │   ├── anomaly_detector.py        # IF + LOF ensemble
│   │   │   └── model_manager.py           # Async model lifecycle
│   │   └── utils/
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Layout/                    # Sidebar, Header, AppLayout
│   │   │   ├── Dashboard/                 # Charts: Traffic, Severity, TopIPs, Anomaly
│   │   │   └── common/                    # StatCard, SeverityBadge, RiskBadge, Spinner
│   │   ├── pages/
│   │   │   ├── DashboardPage.tsx
│   │   │   ├── AlertsPage.tsx
│   │   │   ├── IncidentsPage.tsx          # Incident management
│   │   │   ├── IntelligencePage.tsx       # Threat intelligence
│   │   │   ├── InvestigationPage.tsx      # IP forensics
│   │   │   ├── SOARPage.tsx               # SOAR & playbooks
│   │   │   ├── SOCAssistantPage.tsx       # AI chat assistant
│   │   │   └── EventViewerPage.tsx        # Live event viewer
│   │   ├── services/api.ts                # Axios client with JWT interceptors
│   │   ├── hooks/useWebSocket.ts
│   │   ├── store/authStore.ts             # Zustand auth state
│   │   ├── types/index.ts                 # TypeScript type definitions
│   │   └── utils/formatters.ts
│   ├── package.json
│   ├── vite.config.ts
│   ├── tailwind.config.js
│   ├── nginx.conf
│   └── Dockerfile
├── scripts/
│   ├── init.sql                           # DB initialization
│   └── create_admin.py                    # Initial admin user creation
├── START_BACKEND_ADMIN.bat                # Windows quick-start helper
├── docker-compose.yml
├── .env.example
└── README.md
```

---

## Quick Start

### Prerequisites
- Docker Desktop (or Docker Engine + Compose)
- 8GB RAM recommended (Ollama LLM)
- Optional: NVIDIA GPU for faster LLM inference

### 1. Clone and Configure

```bash
git clone https://github.com/iamasiffiaz/AI-Threat-Detection-System.git
cd "AI Threat Detection System"
cp .env.example .env
# Edit .env and set a strong SECRET_KEY
```

### 2. Start Services

```bash
# Start all services
docker compose up -d

# Pull the Ollama LLM model (first time only, ~4GB)
docker compose --profile setup up ollama-pull

# Create the admin user
docker compose exec backend python scripts/create_admin.py
```

### 3. Access the Application

| Service       | URL                            |
|---------------|--------------------------------|
| Dashboard     | http://localhost:3000          |
| API Docs      | http://localhost:8000/api/docs |
| ReDoc         | http://localhost:8000/api/redoc|

**Default credentials:**
- Username: `admin`
- Password: `Admin1234!`

> Change immediately after first login!

### 4. Generate Test Data

After logging in, go to **Logs → Generate Sample Data** to populate 500 synthetic log entries and trigger automatic rule/ML detection.

Then click **Train ML Model** to train the anomaly detector on the generated data.

---

## Local Development (without Docker)

### Backend

```bash
cd backend

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # Linux/macOS

# Install dependencies
pip install -r requirements.txt

# Set environment variables
cp .env.example .env
# Edit .env with your local PostgreSQL/Redis URLs

# Run development server
uvicorn app.main:app --reload --port 8000
```

### Frontend

```bash
cd frontend

npm install
npm run dev  # Starts on http://localhost:3000
```

---

## API Reference

### Authentication
| Method | Endpoint               | Description               | Auth  |
|--------|------------------------|---------------------------|-------|
| POST   | `/api/v1/auth/login`   | Get JWT tokens            | No    |
| POST   | `/api/v1/auth/refresh` | Refresh access token      | No    |
| GET    | `/api/v1/auth/me`      | Current user profile      | Yes   |
| POST   | `/api/v1/auth/register`| Create user (admin only)  | Admin |

### Log Ingestion
| Method | Endpoint                       | Description                  |
|--------|--------------------------------|------------------------------|
| POST   | `/api/v1/logs/stream`          | Ingest single log entry      |
| POST   | `/api/v1/logs/bulk`            | Ingest batch of log entries  |
| POST   | `/api/v1/logs/upload`          | Upload CSV/JSON/syslog file  |
| GET    | `/api/v1/logs`                 | List logs with pagination    |
| GET    | `/api/v1/logs/statistics`      | Aggregated log statistics    |
| POST   | `/api/v1/logs/generate-sample` | Generate synthetic test data |
| POST   | `/api/v1/logs/train-model`     | Train ML anomaly model       |

### Alerts
| Method | Endpoint                       | Description                  |
|--------|--------------------------------|------------------------------|
| GET    | `/api/v1/alerts`               | List alerts with filters     |
| GET    | `/api/v1/alerts/summary`       | Alert statistics summary     |
| GET    | `/api/v1/alerts/{id}`          | Get specific alert           |
| PATCH  | `/api/v1/alerts/{id}`          | Update alert status          |
| POST   | `/api/v1/alerts/{id}/analyze`  | Trigger LLM analysis         |

### Anomalies
| Method | Endpoint                        | Description                |
|--------|---------------------------------|----------------------------|
| GET    | `/api/v1/anomalies`             | List detected anomalies    |
| GET    | `/api/v1/anomalies/trends`      | Hourly anomaly trends      |
| GET    | `/api/v1/anomalies/top-ips`     | Most anomalous source IPs  |
| GET    | `/api/v1/anomalies/model-info`  | ML model metadata          |

### Incidents
| Method | Endpoint                              | Description                    |
|--------|---------------------------------------|--------------------------------|
| GET    | `/api/v1/incidents`                   | List incidents with filters    |
| GET    | `/api/v1/incidents/summary`           | Incident statistics            |
| GET    | `/api/v1/incidents/{id}`              | Get specific incident          |
| GET    | `/api/v1/incidents/{id}/timeline`     | Alert timeline for incident    |
| PATCH  | `/api/v1/incidents/{id}`              | Update incident status         |
| POST   | `/api/v1/incidents/{id}/escalate`     | Escalate incident severity     |
| DELETE | `/api/v1/incidents/{id}`              | Delete incident (admin only)   |

### Threat Intelligence
| Method | Endpoint                        | Description                    |
|--------|---------------------------------|--------------------------------|
| GET    | `/api/v1/intelligence/ip/{ip}`  | Full TI report for IP          |
| GET    | `/api/v1/intelligence/ip/{ip}/geo` | GeoIP data for IP           |
| POST   | `/api/v1/intelligence/bulk`     | Bulk IP lookup                 |
| GET    | `/api/v1/intelligence/top-threats` | Top threat IPs leaderboard  |

### Investigation
| Method | Endpoint                           | Description                    |
|--------|------------------------------------|--------------------------------|
| GET    | `/api/v1/investigation/ip/{ip}`    | Full forensic report for IP    |
| GET    | `/api/v1/investigation/ip/{ip}/logs` | Recent log history for IP    |
| GET    | `/api/v1/investigation/ip/{ip}/alerts` | Alerts for IP              |
| GET    | `/api/v1/investigation/ip/{ip}/behavior` | Behavioral profile for IP|
| GET    | `/api/v1/investigation/alert/{id}` | Deep-dive on specific alert    |

### SOAR
| Method | Endpoint                           | Description                    |
|--------|------------------------------------|--------------------------------|
| GET    | `/api/v1/soar/blacklist`           | List blocked IPs               |
| GET    | `/api/v1/soar/blacklist/{ip}`      | Check if IP is blocked         |
| POST   | `/api/v1/soar/blacklist`           | Block an IP                    |
| DELETE | `/api/v1/soar/blacklist/{ip}`      | Unblock an IP                  |
| GET    | `/api/v1/soar/playbooks`           | List all playbooks             |
| GET    | `/api/v1/soar/playbooks/{type}`    | Get playbook for attack type   |
| POST   | `/api/v1/soar/respond/{alert_id}`  | Trigger automated response     |
| GET    | `/api/v1/soar/stats`               | SOAR statistics                |

### AI SOC Assistant
| Method | Endpoint                                 | Description                         |
|--------|------------------------------------------|-------------------------------------|
| POST   | `/api/v1/soc-assistant/ask`              | Ask a free-form question            |
| POST   | `/api/v1/soc-assistant/explain/{id}`     | Explain a specific alert            |
| POST   | `/api/v1/soc-assistant/advise/{id}`      | Get remediation advice for alert    |
| POST   | `/api/v1/soc-assistant/incident/{id}`    | Summarize an incident               |
| POST   | `/api/v1/soc-assistant/stream/ask`       | Streaming free-form question        |
| POST   | `/api/v1/soc-assistant/stream/explain/{id}` | Streaming alert explanation    |
| POST   | `/api/v1/soc-assistant/stream/advise/{id}`  | Streaming remediation advice   |
| POST   | `/api/v1/soc-assistant/stream/incident/{id}` | Streaming incident summary    |

### Event Viewer
| Method | Endpoint                            | Description                     |
|--------|-------------------------------------|---------------------------------|
| GET    | `/api/v1/event-viewer/status`       | Viewer status                   |
| POST   | `/api/v1/event-viewer/start`        | Start live monitoring           |
| POST   | `/api/v1/event-viewer/stop`         | Stop live monitoring            |
| GET    | `/api/v1/event-viewer/recent`       | Recent events                   |
| POST   | `/api/v1/event-viewer/pull-now`     | Force-pull from channels        |
| GET    | `/api/v1/event-viewer/channels`     | Channel status                  |
| POST   | `/api/v1/event-viewer/reset-watermarks` | Reset stream watermarks     |
| GET    | `/api/v1/event-viewer/diagnose`     | Diagnose ingestion pipeline     |

### Dashboard
| Method | Endpoint                       | Description               |
|--------|--------------------------------|---------------------------|
| GET    | `/api/v1/dashboard/overview`   | All KPIs in one request   |

### WebSocket
| Endpoint                   | Description                           |
|----------------------------|---------------------------------------|
| `ws://host/ws/alerts`      | Real-time alert stream                |
| `ws://host/ws/logs/stream` | Simulated real-time log stream        |

Authentication: pass `?token=<jwt>` as query parameter.

---

## Configuration Reference

All settings are loaded from environment variables (`.env` file):

| Variable                      | Default      | Description                               |
|-------------------------------|--------------|-------------------------------------------|
| `DATABASE_URL`                | —            | PostgreSQL async connection string        |
| `SECRET_KEY`                  | —            | JWT signing key (min 32 chars)            |
| `OLLAMA_BASE_URL`             | localhost    | Ollama API endpoint                       |
| `OLLAMA_MODEL`                | `llama3`     | LLM model name                            |
| `ABUSEIPDB_API_KEY`           | —            | Optional: AbuseIPDB key for IP reputation |
| `ANOMALY_THRESHOLD`           | `0.6`        | Score above which anomaly alerts fire     |
| `FAILED_LOGIN_THRESHOLD`      | `5`          | Failed logins before brute-force alert    |
| `PORT_SCAN_THRESHOLD`         | `20`         | Unique ports before port scan alert       |
| `MIN_TRAINING_SAMPLES`        | `100`        | Minimum logs required for ML training     |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `60`         | JWT access token lifetime                 |

---

## Deployment

### Production Checklist

- [ ] Set a strong, random `SECRET_KEY` (min 32 chars)
- [ ] Change default `POSTGRES_PASSWORD`
- [ ] Change admin password after first login
- [ ] Configure `ALLOWED_ORIGINS` to your actual domain
- [ ] Enable HTTPS (reverse proxy: Traefik, Nginx, Caddy)
- [ ] Set `DEBUG=false` and `ENVIRONMENT=production`
- [ ] Configure log retention policy in PostgreSQL
- [ ] Set up database backups
- [ ] Monitor with Prometheus + Grafana (metrics endpoint included)
- [ ] Optionally set `ABUSEIPDB_API_KEY` for live IP reputation data

### Scaling

The backend supports **horizontal scaling** — run multiple instances behind a load balancer. ML models are persisted to a shared volume. Redis is used for shared correlation state, blacklist hot-set, and TI caching across all instances.

---

## Screenshots

> Dashboard Overview
> ![Dashboard](docs/screenshots/dashboard.png)

> Alerts Page with LLM Explanation
> ![Alerts](docs/screenshots/alerts.png)

> Anomaly Detection
> ![Anomalies](docs/screenshots/anomalies.png)

---

## License

MIT — see [LICENSE](LICENSE)

---

*Built as a production-grade SOC platform demonstrating ML anomaly detection, LLM-powered threat intelligence, automated incident response (SOAR), real-time correlation, and an AI SOC assistant.*
