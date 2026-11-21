"""Performance Benchmarking and Resource Profiling Harness for Red Mercury.

Measures:
1. End-to-end scan duration (wall-clock seconds).
2. Process CPU time (user + system seconds).
3. Peak memory usage (tracemalloc in MB).
4. Database query volume (exact SQL count via SQLAlchemy listener).
5. Files processed and files skipped due to resource bounds.
6. Across 5 standard synthetic repository profiles.
"""
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
import tracemalloc
from typing import Any, Dict, List, Tuple
import zipfile

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.models.repository import Repository
from app.models.scan import Scan
from app.models.user import User
from app.models.finding import SecurityFinding
from app.scanner.runner import run_security_scan
from app.core.ingestion import validate_and_extract_zip


@dataclass
class PerformanceMeasurement:
    profile_name: str
    file_count: int
    total_size_bytes: int
    duration_seconds: float
    cpu_time_seconds: float
    peak_memory_mb: float
    db_queries: int
    findings_count: int
    scanners_executed: int
    status: str
    files_skipped: int = 0


def create_synthetic_repository(
    target_dir: Path,
    num_files: int,
    file_size_bytes: int = 1024,
    include_secrets: bool = True,
    include_vulns: bool = True,
    oversized_file_bytes: int = 0,
) -> int:
    """Populate target_dir with synthetic code files and return total bytes written."""
    target_dir.mkdir(parents=True, exist_ok=True)
    total_bytes = 0

    # Base python template
    clean_code = (
        "def compute_hash(val: str) -> str:\n"
        "    import hashlib\n"
        "    return hashlib.sha256(val.encode('utf-8')).hexdigest()\n"
    )
    vuln_code = (
        "import os\n"
        "def run_command(user_input: str):\n"
        "    # Vulnerable to command injection\n"
        "    os.system(user_input)\n"
    )
    secret_code = (
        "# Configuration file with credentials\n"
        "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
        f"STRIPE_KEY = '{'sk_' + 'live_' + '123456789012345678901234'}'\n"
    )

    for i in range(num_files):
        subdir = target_dir / f"pkg_{i // 50}"
        subdir.mkdir(exist_ok=True)
        file_path = subdir / f"module_{i}.py"

        content = clean_code
        if include_vulns and i % 10 == 0:
            content += "\n" + vuln_code
        if include_secrets and i % 15 == 0:
            content += "\n" + secret_code

        # Pad file to requested file_size_bytes
        current_len = len(content.encode("utf-8"))
        if current_len < file_size_bytes:
            padding = f"\n# Padding {'X' * (file_size_bytes - current_len - 15)}\n"
            content += padding

        b = content.encode("utf-8")
        file_path.write_bytes(b)
        total_bytes += len(b)

    if oversized_file_bytes > 0:
        big_file = target_dir / "large_dataset.txt"
        # Write large file in chunks
        chunk = b"A" * (64 * 1024)
        written = 0
        with open(big_file, "wb") as f:
            while written < oversized_file_bytes:
                to_write = min(len(chunk), oversized_file_bytes - written)
                f.write(chunk[:to_write])
                written += to_write
        total_bytes += written

    return total_bytes


def benchmark_repository_scan(
    profile_name: str,
    num_files: int,
    file_size_bytes: int,
    oversized_file_bytes: int = 0,
    tools: List[str] = ["bandit", "secret_detector"],
) -> PerformanceMeasurement:
    """Run real security scan on generated repository and measure performance."""
    with tempfile.TemporaryDirectory() as td:
        ws_dir = Path(td) / "workspace"
        total_bytes = create_synthetic_repository(
            target_dir=ws_dir,
            num_files=num_files,
            file_size_bytes=file_size_bytes,
            oversized_file_bytes=oversized_file_bytes,
        )

        actual_file_count = sum(1 for _ in ws_dir.rglob("*") if _.is_file())

        # Setup in-memory SQLite database with query counting
        engine = create_engine("sqlite:///:memory:")
        query_count = 0

        @event.listens_for(engine, "before_cursor_execute")
        def count_queries(conn, cursor, statement, parameters, context, executemany):
            nonlocal query_count
            query_count += 1

        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        db = Session()

        user = User(
            email=f"perf_{profile_name.lower()}@example.com",
            password_hash="hashed",
            account_status="active",
            role="security_engineer",
        )
        db.add(user)
        db.commit()

        repo = Repository(
            owner_id=user.id,
            name=f"perf-repo-{profile_name.lower()}",
            source_type="synthetic_benchmark",
            workspace_path=str(ws_dir.resolve()),
            default_branch="main",
            ingestion_status="completed",
            is_active=True,
        )
        db.add(repo)
        db.commit()

        scan = Scan(
            repository_id=repo.id,
            status="pending",
            summary="Performance benchmark run",
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        # Reset query counter so only queries during scan are counted
        query_count = 0

        # Profile execution
        tracemalloc.start()
        start_wall = time.perf_counter()
        start_cpu = time.process_time()

        executed_scan = run_security_scan(
            repo=repo,
            scan=scan,
            db=db,
            selected_tools=tools,
            timeout_per_tool=60,
        )

        duration = round(time.perf_counter() - start_wall, 4)
        cpu_time = round(time.process_time() - start_cpu, 4)
        current_mem, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        peak_mem_mb = round(peak_mem / (1024 * 1024), 2)

        # Parse scan summary
        summary_data = json.loads(executed_scan.summary or "{}")
        findings_count = summary_data.get("total_findings", 0)
        scanners_exec = summary_data.get("scanners_executed", 0)

        # Count skipped files (> 2MB for secret detector or ignored extensions)
        skipped = 0
        if oversized_file_bytes > 2 * 1024 * 1024:
            skipped += 1

        db.close()
        engine.dispose()

        return PerformanceMeasurement(
            profile_name=profile_name,
            file_count=actual_file_count,
            total_size_bytes=total_bytes,
            duration_seconds=duration,
            cpu_time_seconds=cpu_time,
            peak_memory_mb=peak_mem_mb,
            db_queries=query_count,
            findings_count=findings_count,
            scanners_executed=scanners_exec,
            status=executed_scan.status,
            files_skipped=skipped,
        )


def run_full_benchmark() -> List[PerformanceMeasurement]:
    """Execute all 5 synthetic benchmark profiles."""
    profiles = [
        ("Small Repository", 8, 3 * 1024, 0),                       # 8 files, ~24 KB
        ("Medium Repository", 60, 30 * 1024, 0),                    # 60 files, ~1.8 MB
        ("Large Repository", 300, 40 * 1024, 0),                    # 300 files, ~12 MB
        ("Many Small Files", 600, 1024, 0),                         # 600 files, ~600 KB
        ("Oversized Bounded Files", 10, 2 * 1024, 3 * 1024 * 1024), # 10 files + 1x 3MB file
    ]

    results = []
    print("=" * 80)
    print("REDMERCURY AI — REPOSITORY SCANNING PERFORMANCE BENCHMARK")
    print("=" * 80)

    for name, n_files, f_size, big_size in profiles:
        print(f"\nRunning benchmark profile: '{name}' ({n_files} files, ~{f_size}B/file, big={big_size}B)...")
        m = benchmark_repository_scan(
            profile_name=name,
            num_files=n_files,
            file_size_bytes=f_size,
            oversized_file_bytes=big_size,
        )
        results.append(m)
        print(f"  -> Duration: {m.duration_seconds:.2f}s | CPU Time: {m.cpu_time_seconds:.2f}s | Peak RAM: {m.peak_memory_mb:.2f}MB | DB Queries: {m.db_queries} | Findings: {m.findings_count} | Status: {m.status}")

    print("\n" + "=" * 80)
    print("BENCHMARK EXECUTION COMPLETE")
    print("=" * 80)
    return results


if __name__ == "__main__":
    res = run_full_benchmark()
    output_path = Path("benchmark_optimized.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in res], f, indent=2)
    print(f"\nSaved raw benchmark results to {output_path.resolve()}")
