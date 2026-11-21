"""Populate local development database with realistic developer repositories and findings."""
import sys
from pathlib import Path

# Add backend directory to path
backend_path = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_path))

from app.db.session import SessionLocal
from app.models.user import User
from app.models.repository import Repository
from app.models.finding import SecurityFinding
from app.core.config import settings
from app.core.security import hash_password

if settings.is_production or settings.APP_ENV not in ("development", "local_mock_dev"):
    print(f"[SECURITY ERROR] seed_dev.py execution blocked: Current environment is '{settings.APP_ENV}'.")
    print("Development seed data and credential creation is strictly prohibited in non-development deployments.")
    sys.exit(1)

db = SessionLocal()
try:
    dev_user = db.query(User).filter(User.email == "dev@xerova.com").first()
    if not dev_user:
        dev_user = User(
            id="usr-dev-seed-001",
            email="dev@xerova.com",
            password_hash=hash_password(settings.DEV_SEED_PASSWORD),
            account_status="active",
        )
        db.add(dev_user)
        db.commit()
        db.refresh(dev_user)

    # Reassign existing repos to dev user
    for r in db.query(Repository).all():
        r.owner_id = dev_user.id
    db.commit()

    existing_ids = {r.id for r in db.query(Repository).all()}
    repos_to_add = []
    if "repo-auth-gateway" not in existing_ids:
        repos_to_add.append(Repository(
            id="repo-auth-gateway",
            owner_id=dev_user.id,
            name="xerova/auth-gateway",
            source_type="github",
            git_url="https://github.com/xerova/auth-gateway",
            default_branch="main",
            health_score=84,
            critical_count=1,
            high_count=2,
            medium_count=4,
            low_count=0,
            is_active=True,
        ))
    if "repo-billing-service" not in existing_ids:
        repos_to_add.append(Repository(
            id="repo-billing-service",
            owner_id=dev_user.id,
            name="xerova/billing-service",
            source_type="github",
            git_url="https://github.com/xerova/billing-service",
            default_branch="main",
            health_score=72,
            critical_count=2,
            high_count=3,
            medium_count=1,
            low_count=1,
            is_active=True,
        ))
    if "repo-user-api" not in existing_ids:
        repos_to_add.append(Repository(
            id="repo-user-api",
            owner_id=dev_user.id,
            name="xerova/user-api",
            source_type="github",
            git_url="https://github.com/xerova/user-api",
            default_branch="main",
            health_score=96,
            critical_count=0,
            high_count=0,
            medium_count=2,
            low_count=1,
            is_active=True,
        ))
    if "repo-payment-service" not in existing_ids:
        repos_to_add.append(Repository(
            id="repo-payment-service",
            owner_id=dev_user.id,
            name="xerova/payment-service",
            source_type="github",
            git_url="https://github.com/xerova/payment-service",
            default_branch="main",
            health_score=89,
            critical_count=0,
            high_count=1,
            medium_count=3,
            low_count=2,
            is_active=True,
        ))
    if repos_to_add:
        db.add_all(repos_to_add)
        db.commit()

    existing_find_ids = {f.id for f in db.query(SecurityFinding).all()}
    findings_to_add = []
    if "FIND-418" not in existing_find_ids:
        findings_to_add.append(SecurityFinding(
            id="FIND-418",
            repo_id="repo-auth-gateway",
            cwe="CWE-89: SQL Injection",
            title="Raw SQL Query String Interpolation in user_query.py",
            severity="CRITICAL",
            scanner_name="Semgrep OSS",
            file_path="auth-gateway/src/dao/user_query.py",
            line_number=42,
            status="open",
            code_excerpt="cursor.execute(f'SELECT * FROM users WHERE tenant_id = {tenant_id}')",
            pr_number=418,
            confidence_score=0.98,
        ))
    if "FIND-402" not in existing_find_ids:
        findings_to_add.append(SecurityFinding(
            id="FIND-402",
            repo_id="repo-billing-service",
            cwe="CWE-79: Cross-Site Scripting",
            title="Unescaped HTML rendering in invoice template renderer",
            severity="HIGH",
            scanner_name="Bandit AST",
            file_path="billing/templates/invoice.py",
            line_number=118,
            status="open",
            code_excerpt="return render_template_string(f'<div>Invoice for: {customer_name}</div>')",
            pr_number=402,
            confidence_score=0.92,
        ))
    if "FIND-391" not in existing_find_ids:
        findings_to_add.append(SecurityFinding(
            id="FIND-391",
            repo_id="repo-auth-gateway",
            cwe="CWE-798: Hardcoded Credentials",
            title="Hardcoded JWT signing key fallback in auth handler",
            severity="HIGH",
            scanner_name="Gitleaks",
            file_path="auth-gateway/src/auth/jwt.py",
            line_number=28,
            status="open",
            code_excerpt="JWT_SECRET = os.getenv('JWT_SECRET', 'super-secret-default-key-change-in-prod')",
            pr_number=391,
            confidence_score=0.95,
        ))
    if findings_to_add:
        db.add_all(findings_to_add)
        db.commit()

    print(f"Seed complete: {db.query(Repository).count()} repos, {db.query(SecurityFinding).count()} findings.")
finally:
    db.close()
