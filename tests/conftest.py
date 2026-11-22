"""Pytest fixtures for Red Mercury backend and integration tests."""
import os
import sys
import uuid
import pytest
from typing import Generator
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker, Session

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

# Force test database configuration before importing app
os.environ["APP_ENV"] = "development"
os.environ["DATABASE_URL"] = "sqlite:///./test_redmercury.db"
os.environ.setdefault("SANDBOX_ALLOW_HOST_FALLBACK", "true")

from app.core.config import settings
from app.core.security import create_access_token, hash_password
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models.user import User

# Test SQLite Engine
TEST_DATABASE_URL = "sqlite:///./test_redmercury.db"
test_engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def validate_disposable_test_db_url(url: str, app_env: str = "development") -> None:
    """Fail-closed guard ensuring destructive drop_all() only runs on the disposable SQLite test DB."""
    env_normalized = (app_env or "").strip().lower()
    if env_normalized in ("production", "staging"):
        raise RuntimeError(f"Refusing destructive test DB reset under APP_ENV={app_env!r}.")
    if not url or not isinstance(url, str):
        raise RuntimeError("Refusing destructive test DB reset: empty database URL.")

    parsed = make_url(url)
    if not parsed.drivername.startswith("sqlite"):
        raise RuntimeError(
            f"Refusing destructive test DB reset on non-SQLite dialect {parsed.drivername!r}."
        )

    db_path = (parsed.database or "").strip().replace("\\", "/")
    normalized_name = os.path.basename(db_path)
    if normalized_name != "test_redmercury.db" or db_path not in ("./test_redmercury.db", "test_redmercury.db"):
        raise RuntimeError(
            f"Refusing destructive test DB reset on unexpected SQLite path {db_path!r}; "
            "expected './test_redmercury.db'."
        )


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    """Create test tables before tests, drop them after test session."""
    validate_disposable_test_db_url(
        test_engine.url.render_as_string(hide_password=False),
        os.environ.get("APP_ENV", "development"),
    )
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    yield
    validate_disposable_test_db_url(
        test_engine.url.render_as_string(hide_password=False),
        os.environ.get("APP_ENV", "development"),
    )
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()
    try:
        from app.db.session import engine as app_engine
        app_engine.dispose()
    except Exception:
        pass
    if os.path.exists("./test_redmercury.db"):
        try:
            os.remove("./test_redmercury.db")
        except Exception:
            pass


@pytest.fixture
def db_session() -> Generator[Session, None, None]:
    """Provide a clean transaction-isolated database session."""
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(db_session: Session) -> Generator[TestClient, None, None]:
    """Test client with overridden get_db dependency."""
    from app.core.security import auth_rate_limiter
    auth_rate_limiter.reset()

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    auth_rate_limiter.reset()


@pytest.fixture
def create_test_user(db_session: Session):
    """Factory fixture to create test users with active accounts."""
    def _create_user(
        email: str = None,
        password: str = "P@ssword1234!",
        status: str = "active",
        role: str = "analyst",
    ) -> User:
        user_email = email or f"user_{uuid.uuid4().hex[:8]}@xerova.com"
        user = User(
            email=user_email,
            password_hash=hash_password(password),
            account_status=status,
            role=role,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
        return user
    return _create_user


@pytest.fixture
def auth_client(client: TestClient, create_test_user) -> TestClient:
    """Test client pre-authenticated with Bearer token."""
    user = create_test_user()
    token = create_access_token({"sub": user.id, "email": user.email})
    client.headers["Authorization"] = f"Bearer {token}"
    client.current_user = user
    return client


@pytest.fixture
def user_a(create_test_user) -> User:
    return create_test_user(email=f"alice_{uuid.uuid4().hex[:6]}@xerova.com")


@pytest.fixture
def user_b(create_test_user) -> User:
    return create_test_user(email=f"bob_{uuid.uuid4().hex[:6]}@xerova.com")


@pytest.fixture
def client_a(client: TestClient, user_a: User) -> TestClient:
    token = create_access_token({"sub": user_a.id, "email": user_a.email})
    c = TestClient(app)
    c.headers["Authorization"] = f"Bearer {token}"
    c.user = user_a
    return c


@pytest.fixture
def client_b(client: TestClient, user_b: User) -> TestClient:
    token = create_access_token({"sub": user_b.id, "email": user_b.email})
    c = TestClient(app)
    c.headers["Authorization"] = f"Bearer {token}"
    c.user = user_b
    return c
