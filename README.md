# Threat Intelligence Aggregator

A REST API backend that automatically collects, normalizes, and serves threat intelligence data from multiple open-source feeds. Built with Python/Flask, it aggregates indicators of compromise (IOCs) from CISA, AbuseIPDB, and URLhaus into a unified, searchable database with JWT-authenticated access.

---

## Features

- **Multi-source threat aggregation** — pulls from CISA Known Exploited Vulnerabilities (KEV), AbuseIPDB malicious IP blacklist, and URLhaus malware URL feed
- **Normalized data model** — maps heterogeneous feed formats into a unified `Threat` schema with consistent severity scoring, confidence scores, and IOC fields
- **JWT authentication** — all threat data endpoints require a valid token; register/login flow with bcrypt password hashing
- **Advanced search & filtering** — filter by source, severity, threat type, date range, and confidence score; full-text search across title, description, and threat ID
- **Bookmark system** — authenticated users can bookmark threats and attach analyst notes
- **Statistics endpoint** — aggregated counts by source, severity, and type; 30-day daily trend data
- **Scheduled background sync** — APScheduler runs feed fetches on a configurable interval without blocking the API
- **PostgreSQL + SQLite support** — SQLite for local development, PostgreSQL-ready for production via `DATABASE_URL`

---

## API Reference

All endpoints except `/api/auth/register` and `/api/auth/login` require:
```
Authorization: Bearer <access_token>
```

### Auth
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/auth/register` | Create account, returns JWT |
| POST | `/api/auth/login` | Login, returns JWT |
| GET | `/api/auth/me` | Get current user |

### Threats
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/threats/` | List threats (paginated) |
| GET | `/api/threats/<id>` | Get single threat |
| GET | `/api/threats/stats` | Aggregate statistics |
| POST | `/api/threats/search` | Advanced multi-filter search |
| GET | `/api/threats/bookmarks` | Get user's bookmarked threats |
| POST | `/api/threats/<id>/bookmark` | Bookmark a threat |
| PUT | `/api/threats/<id>/bookmark` | Update bookmark notes |
| DELETE | `/api/threats/<id>/bookmark` | Remove bookmark |

#### Query parameters for `GET /api/threats/`
```
?source=CISA          # Filter by source (CISA, AbuseIPDB, URLhaus)
?severity=critical    # Filter by severity (critical, high, medium, low)
?type=vulnerability   # Filter by threat type
?search=CVE-2024      # Full-text search
?days=7               # Limit to last N days
?page=1&per_page=20   # Pagination
```

### Feeds
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/feeds/fetch/cisa` | Manually trigger CISA sync |
| GET | `/api/feeds/sources` | List configured sources |

---

## Setup

### Prerequisites
- Python 3.9+
- API key from [AbuseIPDB](https://www.abuseipdb.com/) (free tier available)

### Installation

```bash
git clone https://github.com/ConnorOrille/Threat_Intel_Aggregate.git
cd Threat_Intel_Aggregate/backend

python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

### Configuration

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

```env
SECRET_KEY=your-secret-key-here
JWT_SECRET_KEY=your-jwt-secret-here

# Optional: defaults to SQLite if not set
DATABASE_URL=postgresql://user:password@localhost/threat_intel

# API Keys
ABUSEIPDB_API_KEY=your-key-here
VIRUSTOTAL_API_KEY=your-key-here
OTX_API_KEY=your-key-here
```

### Run

```bash
python app.py
```

The API will start on `http://localhost:5000`. On first run, the database tables are created automatically.

### Verify

```bash
curl http://localhost:5000/health
# {"status": "healthy"}

# Register and get a token
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "analyst@example.com", "password": "yourpassword"}'

# Trigger a CISA feed fetch
curl -X POST http://localhost:5000/api/feeds/fetch/cisa \
  -H "Authorization: Bearer <your_token>"

# Query threats
curl "http://localhost:5000/api/threats/?severity=critical&days=30" \
  -H "Authorization: Bearer <your_token>"
```

---

## Project Structure

```
backend/
├── app.py                  # App factory, blueprint registration
├── config.py               # Environment-based configuration
├── models.py               # SQLAlchemy models (User, Threat, Bookmark)
├── requirements.txt
├── routes/
│   ├── auth.py             # Register, login, /me
│   ├── threats.py          # CRUD, search, bookmarks, stats
│   └── feeds.py            # Manual feed trigger endpoints
├── services/
│   ├── cisa_service.py     # CISA KEV feed parser
│   ├── abuseipdb_service.py # AbuseIPDB blacklist fetcher
│   ├── urlhaus_service.py  # URLhaus malware URL fetcher
│   └── scheduler.py        # APScheduler background jobs
└── utils/
    └── auth.py             # Auth helper utilities
```

---

## Data Model

```
Threat
├── threat_id         # Source-native ID (e.g. CVE-2024-1234, IP-1.2.3.4)
├── source            # CISA | AbuseIPDB | URLhaus
├── threat_type       # vulnerability | malicious_ip | malware_url
├── title / description
├── severity          # critical | high | medium | low
├── confidence_score  # 0-100 (where applicable)
├── indicators        # JSON: source-specific IOC fields
├── threat_metadata   # JSON: additional context
└── date_discovered
```

---
