# Red Mercury — Setup & Environment Configuration Notes

## Python Requirements Overview

Red Mercury separates runtime application requirements from test and development requirements to minimize production container attack surface and prevent platform-specific build failures.

### 1. Production Requirements (`backend/requirements.txt`)
Contains core runtime packages required to serve the FastAPI backend and execute standard static code analysis:
- **FastAPI / Uvicorn / Pydantic v2**: Core REST API and data validation
- **SQLAlchemy 2.0 / Alembic**: Database ORM and schema migrations
- **Cryptography / PyJWT / Bcrypt**: Security token signing, password hashing, and encrypted credentials
- **Bandit / pip-audit**: Integrated Python SAST and SCA scanning engines
- **Semgrep OSS (`semgrep>=1.65.0; sys_platform != "win32"`)**: Polyglot AST analysis engine. Platform-gated with environment marker `sys_platform != "win32"` to ensure installation succeeds on native Windows environments without requiring WSL.

Install with:
```bash
pip install -r backend/requirements.txt
```

### 2. Development & Testing Requirements (`backend/requirements-dev.txt`)
Includes all base production dependencies (`-r requirements.txt`) plus frameworks and scientific libraries required for running the comprehensive test suite and machine learning prioritization experiments:
- **pytest / pytest-asyncio**: Test runner and async fixtures
- **httpx**: Async HTTP client for FastAPI `TestClient`
- **numpy / scikit-learn / joblib**: Machine learning models and feature extraction for evidence deficit prediction experiments

Install with:
```bash
pip install -r backend/requirements-dev.txt
```

### 3. Running Backend Tests
Execute the Pytest test suite using:
```bash
# Set PYTHONPATH to include project root and backend:
# Windows PowerShell:
$env:PYTHONPATH=".;./backend"
python -m pytest tests/ -v

# Linux / macOS:
PYTHONPATH=".:./backend" pytest tests/ -v
```
