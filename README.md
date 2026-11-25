# Cloud-Sentry

**Cloud Sentry — Cloud Storage Access Control & Security Misconfiguration Simulator**

An educational cybersecurity project built with **Python**, **Streamlit**, **Pandas**, and local **JSON** storage (100% local — no external cloud providers).

## Features

- **Simulated Cloud Storage Objects**: Manage objects with sensitivity classifications (`Public`, `Internal`, `Confidential`, `Restricted`) and policies (`public-read`, `private`, `role-restricted`).
- **Dynamic Users & RBAC Roles**: Create, edit, and delete users across `Admin`, `Manager`, `Employee`, and `Guest` roles.
- **Deterministic Access-Control Engine**: Evaluates `READ`, `WRITE`, and `DELETE` requests with clear `ALLOW` / `DENY` explanations.
- **Independent Expected Access Matrix**: Compares predefined expected `READ` permissions against actual policy evaluations (`PASS` / `FAIL`).
- **Misconfiguration & Educational Risk Analyzer**: Detects dangerous cloud storage misconfigurations (e.g., `Confidential` or `Restricted` data set to `public-read`), computes an educational heuristic risk score (`0–100`), and generates remediation recommendations.
- **Local Audit Logging**: Tracks every simulated access attempt locally with summary metrics and CSV export.
- **Automated & Custom Security Tests**: Built-in verification suite plus an interactive custom test builder.

## Project Structure

```text
app.py                # Streamlit dashboard (Light & Dark monochrome UI)
access_control.py     # Deterministic access-control engine
risk_analyzer.py      # Misconfiguration scanner & educational risk scorer
models.py             # Typed data models & local JSON persistence
test_cases.py         # Expected READ access matrix & automated tests
requirements.txt      # Python dependencies
data/
  users.json          # Simulated user identities
  objects.json        # Simulated cloud storage objects
utils/
  __init__.py
  logger.py           # Local JSON audit logger & metrics
```

## Run Locally

```powershell
# Activate virtual environment (Windows PowerShell)
.\venv\Scripts\Activate.ps1

# Install dependencies (if needed)
pip install -r requirements.txt

# Launch Cloud Sentry dashboard
streamlit run app.py

# Run automated CLI security tests
python test_cases.py
```
