# GDMS — Guard Duty Management System

GDMS is a Flask-based web application for maintaining guard records, entering daily post-wise duty results, recording Rest/Leave availability, managing user accounts, and reviewing guard-wise duty statistics.

> **Version scope:** This README documents the current single-organization codebase in this project archive. It does not describe the planned multi-organization/SaaS architecture; tenant onboarding, tenant isolation, and configurable organization-specific duty rules are not implemented in this version.

## Current capabilities

## Application Screenshots

### Dashboard
![Dashboard](./screenshots/Dashboard.png)

### Guard Management
![Guard Management](./screenshots/Guards.png)

### Duty Roster
![Duty Roster](./screenshots/Duty%20Roster.png)

### Duty Analytics
![Duty Analytics](./screenshots/Duty%20Analytics.png)
- **Login and roles:** authenticated access using Flask-Login. Supported roles are `ADMIN`, `SUPERVISOR`, and `VIEWER`.
- **Dashboard:** application landing page and navigation to the main modules.
- **Guard management:** add guards, edit guard names, and activate/deactivate guard records. Guard IDs are sorted naturally (for example, `G2` before `G10`).
- **Daily Duty Entry:** enter duty records by duty date for the configured post/shift slots. Each date sheet is configured for 15 slots. Results include `PENDING`, `PRESENT`, `REPLACED`, `ABSENT`, `REST`, `LEAVE`, and `CANCELLED`.
- **Rest & Leave Management:** set each active guard's date-wise status to Available, Rest, or Leave. Available is represented by no Rest/Leave record; only `REST` and `LEAVE` are stored. The page supports saving the date's changes together.
- **Duty Analytics:** select a start and end date and review day duties, night duties, and total credited duties by guard. `PRESENT` and `REPLACED` duties are credited to the actual guard. Table headings can be clicked to sort the displayed results.
- **User management:** Admin users can create and update accounts, assign roles, activate/deactivate accounts, and optionally reset passwords. Passwords must be at least eight characters. The account named `Admin` (case-insensitive) has special protection in the current implementation.

## Current duty configuration

The current application code expects exactly **15 active post/shift combinations** when saving a daily duty sheet.

| Post | Shift 1 | Shift 2 | Shift 3 |
|---|:---:|:---:|:---:|
| P1 | Yes | Yes | Yes |
| P2 | Yes | Yes | Yes |
| P4 | Yes | Yes | Yes |
| PTL | Yes | Yes | No |
| BM | Yes | Yes | No |
| OP | Yes | Yes | No |

| Shift | Timing |
|---|---|
| Shift 1 | 06:00–14:00 |
| Shift 2 | 14:00–21:00 |
| Shift 3 | 21:00–06:00 (next day) |

The duty date for Shift 3 is the date on which that shift starts at 21:00. The roster page validates that the active post/shift combinations total 15. Changing the number of slots requires corresponding application/database changes; this version is not yet a dynamic duty engine.

## Technology stack

- Python and Flask
- Flask-Login
- Flask-WTF and WTForms
- PyMySQL
- MySQL-compatible TiDB Cloud database
- Jinja2 templates, HTML, CSS, and JavaScript
- Gunicorn for production serving
- python-dotenv for local environment configuration

Pinned Python dependencies are listed in `requirements.txt`.

## Project structure

```text
GDMS Backup/
├── app.py                  # Flask application, routes, and application logic
├── config.py               # Environment-based configuration
├── create_admin.py         # Command-line Admin account creation utility
├── test_tidb.py            # TiDB connection test utility
├── requirements.txt        # Python dependencies
├── Procfile                # Render/Gunicorn start command
├── .gitignore              # Excludes local environment and Python cache files
├── certs/
│   └── isrgrootx1.pem      # CA certificate used for the TiDB SSL connection
└── templates/
    ├── analytics.html
    ├── attendance.html
    ├── availability.html
    ├── dashboard.html
    ├── guards.html
    ├── login.html
    ├── roster.html
    └── users.html
```

## Database

The application connects to a TiDB/MySQL-compatible database using PyMySQL and SSL. The database and its tables must already exist; this source archive does not include a database schema or migration file.

The current codebase uses these tables:

| Table | Purpose |
|---|---|
| `users` | Login accounts, password hashes, roles, and account status |
| `guards` | Guard IDs, names, and active status |
| `posts` | Duty posts |
| `shifts` | Shift names and timings |
| `post_shift_availability` | Active post/shift combinations |
| `duty_slots` | Date-wise duty slot, planned guard, actual guard, result, and notes |
| `guard_day_status` | Date-wise Rest/Leave records |

**Schema note:** The consolidated source update notes state that no database DDL/schema changes were included in that update. Do not assume that extracting this ZIP creates or migrates database tables.

## Local setup

### Requirements

- Python 3.10 or a compatible newer Python version
- Access to the configured TiDB/MySQL database
- The existing database tables listed above
- The CA certificate at `certs/isrgrootx1.pem` (or the path configured through the environment)

### 1. Create and activate a virtual environment

Windows PowerShell:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, use Command Prompt:

```bat
.venv\Scripts\activate.bat
```

### 2. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Configure environment variables

Create a local `.env` file in the same directory as `app.py`. Use your own values and do not commit this file.

The Flask application reads:

```dotenv
SECRET_KEY=replace-with-a-long-random-secret
TIDB_HOST=your-tidb-host
TIDB_PORT=4000
TIDB_USER=your-tidb-user
TIDB_PASSWORD=your-tidb-password
TIDB_NAME=gdms
TIDB_SSL_CA=certs/isrgrootx1.pem
```

`TIDB_SSL_CA` is resolved relative to the project directory. The default configured path is `certs/isrgrootx1.pem`.

`config.py` also defines `DB_HOST`, `DB_USER`, `DB_PASSWORD`, and `DB_NAME` for local MySQL configuration. **The included `create_admin.py` utility currently uses those `DB_*` variables, while the running Flask application connects using the `TIDB_*` variables.** If using that utility with TiDB, configure the `DB_*` values to point to the intended database as well, or use an approved alternative Admin-provisioning method. Never put credentials in source files or Git.

### 4. Run locally

```bash
python app.py
```

Open the local URL printed by Flask (normally `http://127.0.0.1:5000`).

## User roles

| Role | Current access |
|---|---|
| `ADMIN` | Full application access, including user management |
| `SUPERVISOR` | Operational access such as guard management, duty entry, and Rest/Leave updates; cannot manage users |
| `VIEWER` | Read-only access to operational pages; cannot submit operational changes or manage users |

Permissions are checked in route handlers, with controls also conditionally displayed in templates.

## Deployment on Render

The included `Procfile` contains:

```text
web: gunicorn app:app
```

Typical Render settings:

- **Runtime:** Python
- **Build command:** `pip install -r requirements.txt`
- **Start command:** `gunicorn app:app`

Configure these environment variables in the Render service settings:

- `SECRET_KEY`
- `TIDB_HOST`
- `TIDB_PORT`
- `TIDB_USER`
- `TIDB_PASSWORD`
- `TIDB_NAME`
- `TIDB_SSL_CA` (if using a non-default certificate path)

Keep credentials in Render's environment settings. Do not upload `.env` to GitHub. The application uses an external database, which must remain reachable from Render. When a commit is pushed to the connected GitHub branch, Render can deploy it according to the service's deployment settings.

## Git and secret-file safety

The included `.gitignore` excludes:

```gitignore
.env
.venv/
__pycache__/
*.pyc
```

Before committing, verify that `.env`, database dumps, private keys, access tokens, and other secrets are not staged or tracked. Useful checks:

```bash
git status
git ls-files
```

If `.env` was previously committed, adding it to `.gitignore` does not remove it from Git history or stop tracking it. Remove it from tracking and rotate any exposed credentials.

## Current implementation boundaries

This codebase is configured for one organization and a fixed 15-slot duty arrangement. It does **not** yet implement:

- Multiple organizations or tenant isolation
- Organization self-registration or manual tenant provisioning
- Organization-specific configurable duty rules
- Dynamic numbers of posts, shifts, or duty slots
- Cross-organization account or data management

These items belong to a future architecture and migration project. The existing database must not be reset to prepare for that work; any future schema migration should be backed up, reviewed, tested, and approved before it is applied to production.

## Current project notes

The latest consolidated source update includes the Rest & Leave bulk-save behavior, sortable duty analytics, and user-management improvements described above. Its update notes state that no database DDL/schema changes were added. This README documents the source archive; it does not independently certify that a production deployment or live database has been tested.

## License

No license file or license terms are included in this project archive. Add a `LICENSE` file before publishing the repository for reuse or redistribution.
