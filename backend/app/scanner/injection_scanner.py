"""SQL and NoSQL Injection detection engine.

Detects:
1. SQL Injection (CWE-89):
   - Raw string interpolation/concatenation in SQL queries across Python, JavaScript/Node.js, PHP, and Java.
   - Unparameterized ORM raw queries (SQLAlchemy text(), Django raw(), Sequelize query(), Knex raw()).
2. NoSQL Injection (CWE-943):
   - Unsanitized request bodies passed directly to MongoDB/Mongoose find/findOne/update/delete.
   - MongoDB $where clause containing dynamic string concatenation (eval-in-db).
   - PyMongo unescaped dictionary operator queries allowing authentication bypass ($gt, $ne, $regex).
"""
from pathlib import Path
import re
import time
from typing import Any, Dict, List, Optional

from .base import (
    BaseScannerAdapter,
    NormalizedFinding,
    ScanJobResult,
    ScannerStatus,
)
from ..core.logging import get_logger

logger = get_logger("redmercury.scanner.injection")

# SQL Injection Patterns (CWE-89)
SQL_INJECTION_PATTERNS = [
    # Python: cursor.execute("SELECT ... " + var) or f"SELECT ... {var}"
    (
        re.compile(r"""(\.execute|\.raw|\.executescript)\s*\(\s*(f["']|["'].*?\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b.*?(["']\s*\+|\+\s*["']|\{.*?\}|%\s*[a-zA-Z0-9_]+|\.format\s*\())""", re.IGNORECASE),
        "SQLI-STRING-CONCATENATION",
        "CRITICAL",
        "CWE-89",
        "Raw SQL query constructed via string concatenation, formatting, or f-strings; use parameterized query binding (? or :param).",
    ),
    # SQLAlchemy text() with string concatenation
    (
        re.compile(r"""text\s*\(\s*(f["']|["'].*?\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b.*?["']\s*\+)""", re.IGNORECASE),
        "SQLI-SQLALCHEMY-RAW-TEXT-CONCAT",
        "CRITICAL",
        "CWE-89",
        "SQLAlchemy text() clause constructed with unparameterized string concatenation; bind parameters via text(...).bindparams().",
    ),
    # Node.js: db.query("SELECT ... " + id) or db.query(`SELECT ... ${id}`)
    (
        re.compile(r"""(\.query|\.raw|\.execute)\s*\(\s*(`.*?\b(SELECT|INSERT|UPDATE|DELETE|WHERE)\b.*?(\$\{.*?\})|["'].*?\b(SELECT|INSERT|UPDATE|DELETE)\b.*?["']\s*\+)""", re.IGNORECASE),
        "SQLI-NODEJS-UNESCAPED-QUERY",
        "CRITICAL",
        "CWE-89",
        "SQL query executed using ES6 template literal or string concatenation; use parameterized queries ($1, $2, ?).",
    ),
    # PHP: mysqli_query / PDO::query with concatenation
    (
        re.compile(r"""(mysqli_query|mysql_query|\$pdo->query)\s*\([^,)]*\.\s*\$_(GET|POST|REQUEST|COOKIE)""", re.IGNORECASE),
        "SQLI-PHP-DIRECT-INPUT-CONCAT",
        "CRITICAL",
        "CWE-89",
        "Direct concatenation of superglobal $_GET/$_POST into SQL query; prepare query using PDO::prepare().",
    ),
    # Java: Statement.executeQuery with concatenation
    (
        re.compile(r"""statement\.execute(Query|Update)?\s*\(\s*["'].*?\b(SELECT|INSERT|UPDATE|DELETE)\b.*?["']\s*\+""", re.IGNORECASE),
        "SQLI-JAVA-STATEMENT-CONCAT",
        "CRITICAL",
        "CWE-89",
        "java.sql.Statement used with dynamic query concatenation; use java.sql.PreparedStatement instead.",
    ),
]

# NoSQL Injection Patterns (CWE-943)
NOSQL_INJECTION_PATTERNS = [
    # Mongoose/MongoDB: passing req.body or req.query directly into find/findOne/update/delete
    (
        re.compile(r"""\.(find|findOne|update|updateOne|updateMany|delete|deleteOne|deleteMany)\s*\(\s*(req\.(body|query|params)|data|payload)\s*[,)]""", re.IGNORECASE),
        "NOSQLI-MONGOOSE-UNSANITIZED-QUERY-OBJECT",
        "CRITICAL",
        "CWE-943",
        "Direct user-controlled request object passed to MongoDB query, allowing operator injection ($ne, $gt) for authentication bypass.",
    ),
    # MongoDB $where with string concatenation
    (
        re.compile(r"""\$where\s*:\s*(f["']|["'].*?["']\s*\+|\+.*?["']|`.*?\$\{.*?\}|["'].*?\bthis\b.*?["']\s*\+)""", re.IGNORECASE),
        "NOSQLI-MONGODB-WHERE-CLAUSE-INJECTION",
        "CRITICAL",
        "CWE-943",
        "MongoDB $where clause constructs JavaScript dynamically; allows arbitrary JavaScript execution within database engine.",
    ),
    # PyMongo: raw unvalidated dict passed to query
    (
        re.compile(r"""db\.[a-zA-Z0-9_]+\.find\s*\(\s*\{[^}]*:\s*request\.(json|args|form)\[""", re.IGNORECASE),
        "NOSQLI-PYMONGO-RAW-DICT-INJECTION",
        "HIGH",
        "CWE-943",
        "PyMongo query incorporates unvalidated JSON input directly; potential MongoDB query selector injection.",
    ),
]


class InjectionScannerAdapter(BaseScannerAdapter):
    """Adapter for detecting SQL and NoSQL Injection vulnerabilities across multi-language codebases."""

    name: str = "injection_scanner"
    display_name: str = "SQL & NoSQL Injection Scanner"
    category: str = "sast"

    def is_available(self) -> bool:
        return True

    def get_version(self) -> Optional[str]:
        return "1.0.0-injection-ast"

    def scan(
        self,
        target_dir: Path,
        scan_id: str,
        timeout_seconds: int = 60,
        options: Optional[Dict[str, Any]] = None,
    ) -> ScanJobResult:
        start_time = time.time()
        findings: List[NormalizedFinding] = []

        code_extensions = [".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".java", ".go"]
        for ext in code_extensions:
            for file_path in target_dir.rglob(f"*{ext}"):
                if not file_path.is_file() or any(p in file_path.parts for p in (".git", "node_modules", "venv", ".venv")):
                    continue
                try:
                    rel_path = str(file_path.relative_to(target_dir)).replace("\\", "/")
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    lines = content.splitlines()

                    for idx, line in enumerate(lines, start=1):
                        line_stripped = line.strip()
                        if not line_stripped or line_stripped.startswith("//") or line_stripped.startswith("#"):
                            continue

                        # 1. SQL Injection checks
                        for pattern, rule_id, sev, cwe, msg in SQL_INJECTION_PATTERNS:
                            if pattern.search(line):
                                findings.append(
                                    NormalizedFinding(
                                        scan_id=scan_id,
                                        scanner_name=self.name,
                                        scanner_rule_id=rule_id,
                                        vulnerability_category="sql_injection",
                                        severity=sev,
                                        confidence="HIGH",
                                        file_path=rel_path,
                                        start_line=idx,
                                        end_line=idx,
                                        scanner_message=msg,
                                        evidence_reference=line_stripped[:200],
                                        cwe=cwe,
                                    )
                                )

                        # 2. NoSQL Injection checks
                        for pattern, rule_id, sev, cwe, msg in NOSQL_INJECTION_PATTERNS:
                            if pattern.search(line):
                                findings.append(
                                    NormalizedFinding(
                                        scan_id=scan_id,
                                        scanner_name=self.name,
                                        scanner_rule_id=rule_id,
                                        vulnerability_category="nosql_injection",
                                        severity=sev,
                                        confidence="HIGH",
                                        file_path=rel_path,
                                        start_line=idx,
                                        end_line=idx,
                                        scanner_message=msg,
                                        evidence_reference=line_stripped[:200],
                                        cwe=cwe,
                                    )
                                )
                except Exception as e:
                    logger.debug(f"Error analyzing file {file_path} for injections: {e}")

        return ScanJobResult(
            scanner_name=self.name,
            scanner_version=self.get_version(),
            category=self.category,
            status=ScannerStatus.SUCCESS if findings else ScannerStatus.NO_FINDINGS,
            execution_time_seconds=round(time.time() - start_time, 3),
            findings=findings,
            exit_code=0,
        )
