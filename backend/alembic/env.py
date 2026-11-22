import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool, text

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.core.config import settings
from app.db.base import Base
import app.models  # Ensure all model classes register with Base.metadata

config = context.config

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Set database URL dynamically from app settings unless explicitly overridden on Config
existing_cfg_url = config.get_main_option("sqlalchemy.url")
if not existing_cfg_url or existing_cfg_url == "sqlite:///./redmercury.db":
    config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        is_pg = connection.dialect.name == "postgresql"
        if is_pg:
            # Serialize concurrent multi-replica startup migrations via PostgreSQL advisory lock
            connection.execute(text("SELECT pg_advisory_lock(72839104)"))
            connection.commit()
        try:
            if is_pg:
                connection.execute(text(
                    "CREATE TABLE IF NOT EXISTS alembic_version ("
                    "version_num VARCHAR(128) NOT NULL, "
                    "CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num))"
                ))
                connection.execute(text(
                    "ALTER TABLE alembic_version ALTER COLUMN version_num TYPE VARCHAR(128)"
                ))
                connection.commit()

            context.configure(
                connection=connection,
                target_metadata=target_metadata,
            )

            with context.begin_transaction():
                context.run_migrations()
        finally:
            if is_pg:
                try:
                    connection.execute(text("SELECT pg_advisory_unlock(72839104)"))
                    connection.commit()
                except Exception:
                    pass


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
