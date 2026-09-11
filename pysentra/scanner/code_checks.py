"""Universal language-agnostic static code and dependency scanner."""

import json
import re
from pathlib import Path
from typing import Callable, List, Set, Tuple

import requests

from pysentra.report.cvss import base_score
from pysentra.report.models import Finding

from .common import VECTORS

MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB cap

DEFAULT_IGNORE_DIRS = {
    ".git",
    ".svn",
    ".hg",
    "node_modules",
    "venv",
    ".venv",
    "env",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "pysentra-reports",
    ".idea",
    ".vscode",
    ".tox",
    ".eggs",
    "target",
    "vendor",
    "bin",
    "obj",
    ".tmp",
    "coverage",
    ".next",
    ".nuxt",
}

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".pdf",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar", ".exe", ".dll",
    ".so", ".dylib", ".pyc", ".pyo", ".class", ".jar", ".war", ".ear",
    ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".mov", ".avi",
    ".iso", ".bin", ".dat", ".pkl", ".sqlite", ".db",
}

SENSITIVE_FILENAMES = {
    ".env": ("Critical", "Environment file containing credentials in directory root."),
    ".env.local": ("Critical", "Local environment file found in directory."),
    ".env.production": ("Critical", "Production environment file found in directory."),
    ".env.prod": ("Critical", "Production environment file found in directory."),
    ".env.staging": ("Critical", "Staging environment file found in directory."),
    "id_rsa": ("Critical", "Private RSA SSH key found in filesystem."),
    "id_ed25519": ("Critical", "Private Ed25519 SSH key found in filesystem."),
    "id_dsa": ("Critical", "Private DSA SSH key found in filesystem."),
    "id_ecdsa": ("Critical", "Private ECDSA SSH key found in filesystem."),
    "application_default_credentials.json": ("Critical", "GCP default credentials file exposed in directory."),
    "service-account.json": ("Critical", "GCP service account private key file exposed in directory."),
}

SENSITIVE_FILE_EXTENSIONS = {
    ".pem": ("High", "Certificate/Private key file (.pem) present in directory."),
    ".key": ("High", "Private key file (.key) present in directory."),
    ".p12": ("High", "PKCS#12 certificate/key archive present in directory."),
    ".pfx": ("High", "PFX certificate/key archive present in directory."),
    ".dump": ("Medium", "Database dump file present in directory."),
}

# Regex patterns for secrets & credentials
SECRET_PATTERNS = [
    (
        "AWS Access Key ID",
        re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])"),
        "Critical",
        "Found hardcoded AWS Access Key ID in source file.",
        "Revoke the AWS key in IAM immediately and load credentials from IAM roles or AWS Secrets Manager.",
    ),
    (
        "GCP API Key",
        re.compile(r"(?<![A-Za-z0-9_])(AIza[0-9A-Za-z\-_]{35})(?![A-Za-z0-9_])"),
        "High",
        "Found hardcoded Google Cloud Platform (GCP) API key.",
        "Rotate the GCP API key and configure restrictive constraints in the Google Cloud Console.",
    ),
    (
        "Stripe Secret Key",
        re.compile(r"(?<![a-zA-Z0-9_])(sk_live_[0-9a-zA-Z]{24,})(?![a-zA-Z0-9_])"),
        "Critical",
        "Found hardcoded Stripe live secret key.",
        "Roll the Stripe secret key in the Stripe Dashboard and inject it securely via environment variables.",
    ),
    (
        "Private Key Block",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "Critical",
        "Found embedded private key block in repository file.",
        "Remove the private key from source control, revoke the corresponding key pair, and rotate credentials.",
    ),
    (
        "Database Connection URI with Credentials",
        re.compile(r"(?:postgres|postgresql|mysql|mongodb|redis):\/\/[a-zA-Z0-9_\-\.]+:[^@\s'\"<>]+@[a-zA-Z0-9_\-\.]+"),
        "High",
        "Found database connection URI containing plaintext credentials.",
        "Store database credentials in environment variables and use a secrets manager.",
    ),
    (
        "Hardcoded Secret / API Token",
        re.compile(r"""(?i)\b(?:api[_-]?key|auth[_-]?token|access[_-]?token|secret[_-]?key|client[_-]?secret)\s*[:=]\s*['"]([A-Za-z0-9_\-\.]{16,})['"]"""),
        "High",
        "Potential hardcoded API token or secret key found.",
        "Remove hardcoded tokens from source code and load them from environment variables at runtime.",
    ),
    (
        "Hardcoded Password",
        re.compile(r"""(?i)\b(?:password|passwd|pwd)\s*[:=]\s*['"]([^'"]{8,})['"]"""),
        "Medium",
        "Potential hardcoded password found in source code.",
        "Remove hardcoded passwords and use secure environment configuration or secret storage.",
    ),
]

# Regex patterns for insecure configurations
CONFIG_PATTERNS = [
    (
        "Debug Mode Enabled in Code",
        re.compile(r"""(?i)\b(?:DEBUG\s*=\s*True|app\.debug\s*=\s*True|debug\s*=\s*True|["']DEBUG["']\s*:\s*True|NODE_ENV\s*===?\s*['"]development['"])"""),
        "Medium",
        "Debug mode appears to be hardcoded as enabled in application configuration.",
        "Ensure debug mode is disabled in production environments and configured via environment variables.",
    ),
    (
        "Wildcard CORS Configuration",
        re.compile(r"""(?i)(?:Access-Control-Allow-Origin['"]?\s*[:=]\s*['"]\*['"]|cors\(\s*\{\s*origin\s*:\s*['"]\*['"]|allow_origins\s*=\s*\[\s*['"]\*['"]\s*\])"""),
        "Medium",
        "Wildcard CORS origin (*) detected in code.",
        "Specify explicit trusted origins instead of wildcard '*' when sensitive data or authentication is involved.",
    ),
    (
        "TLS Certificate Verification Disabled",
        re.compile(r"""(?i)\b(?:verify\s*=\s*False|verify_ssl\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?|InsecureRequestWarning)"""),
        "High",
        "TLS/SSL certificate verification is explicitly disabled in network requests.",
        "Enable TLS verification (verify=True) to prevent Man-in-the-Middle (MitM) attacks.",
    ),
]

# Regex patterns for static code injection risks (Informational/Low)
INJECTION_PATTERNS = [
    (
        "Potential Dynamic Code Execution (eval)",
        re.compile(r"\beval\s*\("),
        {".py", ".js", ".ts", ".jsx", ".tsx", ".php"},
        "Low",
        "Dynamic code execution eval() detected. Untrusted input can lead to Arbitrary Code Execution.",
        "Avoid eval(). Use safe parsers such as ast.literal_eval, JSON.parse, or specific schema validators.",
    ),
    (
        "Potential Dynamic Code Execution (exec)",
        re.compile(r"\bexec\s*\("),
        {".py"},
        "Low",
        "Dynamic execution exec() detected. Untrusted input could execute arbitrary code.",
        "Refactor logic to eliminate exec() calls with dynamic strings.",
    ),
    (
        "Potential Command Injection (subprocess shell=True)",
        re.compile(r"subprocess\.(?:Popen|run|call|check_output|check_call)\s*\([^)]*shell\s*=\s*True"),
        {".py"},
        "Medium",
        "Subprocess invocation with shell=True detected. If arguments contain user input, shell injection is possible.",
        "Pass arguments as a list without shell=True, or sanitize arguments thoroughly.",
    ),
    (
        "Potential Insecure Deserialization (pickle.loads)",
        re.compile(r"\bpickle\.loads?\s*\("),
        {".py"},
        "Medium",
        "Use of pickle.loads() detected. Deserializing untrusted pickle payloads can result in remote code execution.",
        "Use safer serialization formats like JSON, MessagePack, or Protocol Buffers.",
    ),
    (
        "Potential Dynamic Function Evaluation (new Function)",
        re.compile(r"new\s+Function\s*\("),
        {".js", ".ts", ".jsx", ".tsx"},
        "Low",
        "Dynamic function constructor `new Function(...)` detected, which behaves similarly to eval().",
        "Avoid dynamic function constructors; use structured function dispatch instead.",
    ),
    (
        "Potential XSS via dangerouslySetInnerHTML",
        re.compile(r"dangerouslySetInnerHTML\s*="),
        {".js", ".ts", ".jsx", ".tsx"},
        "Low",
        "Use of dangerouslySetInnerHTML detected in frontend component.",
        "Sanitize HTML content using DOMPurify before rendering, or prefer safe React text rendering.",
    ),
    (
        "Potential Insecure Deserialization (PHP unserialize)",
        re.compile(r"\bunserialize\s*\("),
        {".php"},
        "Medium",
        "Use of PHP unserialize() detected. Deserializing untrusted input can lead to object injection.",
        "Use json_decode() / json_encode() for data interchange instead of PHP serialize.",
    ),
    (
        "Potential SQL String Concatenation",
        re.compile(r"""(?i)(?:SELECT\s+.+\s+FROM\s+|INSERT\s+INTO\s+|UPDATE\s+.+\s+SET\s+|DELETE\s+FROM\s+)[^"']*\s*\+\s*[a-zA-Z_]"""),
        {".py", ".js", ".ts", ".java", ".php", ".go", ".rb", ".cs"},
        "Low",
        "Potential dynamic SQL string concatenation detected.",
        "Use parameterized queries, prepared statements, or ORM parameter binding.",
    ),
]


def create_code_finding(
    scope: str,
    title: str,
    description: str,
    component: str,
    severity: str,
    snippet: str,
    remediation: str,
) -> Finding:
    """Create a standardized Finding for local code scans."""
    vector = VECTORS.get(severity, VECTORS["Info"])
    return Finding(
        title=title,
        scope_area=scope,
        description=description,
        affected_component=component,
        severity=severity,
        cvss_score=base_score(vector),
        cvss_vector=vector,
        steps_to_reproduce=[
            f"Open file '{component}'.",
            "Inspect the identified line / snippet.",
            "Verify whether secret or untrusted input flows into this location.",
        ],
        poc_request=f"File: {component}",
        poc_response_snippet=snippet[:500] if snippet else "",
        business_impact="Vulnerabilities in source code or exposed secrets may compromise systems and data.",
        remediation=remediation,
    )


def is_binary_file(path: Path) -> bool:
    """Quickly check if a file is binary using extension and byte header inspection."""
    if path.suffix.lower() in BINARY_EXTENSIONS:
        return True
    try:
        with open(path, "rb") as f:
            chunk = f.read(1024)
            if b"\x00" in chunk:
                return True
        return False
    except Exception:
        return True


def parse_gitignore(root_dir: Path) -> Set[str]:
    """Parse basic ignored patterns from root .gitignore."""
    ignored: Set[str] = set()
    gi = root_dir / ".gitignore"
    if gi.is_file():
        try:
            for line in gi.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    ignored.add(line.strip("/"))
        except Exception:
            pass
    return ignored


def should_skip_path(path: Path, root_dir: Path, custom_ignored: Set[str]) -> bool:
    """Check if a path should be skipped during directory traversal."""
    if path == root_dir:
        return False
    parts = path.relative_to(root_dir).parts
    dir_parts = parts[:-1] if path.is_file() else parts
    if any(p in DEFAULT_IGNORE_DIRS for p in dir_parts):
        return True
    if any(p in custom_ignored for p in parts):
        return True
    return False


def is_false_positive_secret(line: str) -> bool:
    """Filter out common placeholder patterns and dummy test values."""
    lower = line.lower()
    placeholders = (
        "placeholder", "your_api_key", "your-api-key", "your_secret",
        "your-secret", "example", "dummy", "change_me", "changeme",
        "xxxxxxxx", "todo", "fixme", "test_key", "sample", "replace_with",
        "os.getenv", "os.environ", "process.env", "get_secret", "secrets.",
        "config(", "${", "<your", "...", "''", '""',
    )
    return any(p in lower for p in placeholders)


def check_file_contents(file_path: Path, rel_str: str) -> List[Finding]:
    """Perform single-pass inspection on a source code file."""
    findings: List[Finding] = []
    suffix = file_path.suffix.lower()

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings

    lines = content.splitlines()

    for line_idx, line in enumerate(lines, start=1):
        line_strip = line.strip()
        if not line_strip or line_strip.startswith(("//", "#", "/*", "*", "<!--")):
            continue

        loc_str = f"{rel_str}:{line_idx}"

        # 1. Secrets check
        for name, pattern, severity, desc, remediation in SECRET_PATTERNS:
            if pattern.search(line):
                if is_false_positive_secret(line) and name not in (
                    "AWS Access Key ID", "Stripe Secret Key", "Private Key Block"
                ):
                    continue
                findings.append(
                    create_code_finding(
                        scope="Source Code Security & Secrets",
                        title=name,
                        description=desc,
                        component=loc_str,
                        severity=severity,
                        snippet=line_strip,
                        remediation=remediation,
                    )
                )

        # 2. Insecure Config check
        for name, pattern, severity, desc, remediation in CONFIG_PATTERNS:
            if pattern.search(line):
                findings.append(
                    create_code_finding(
                        scope="Insecure Configuration",
                        title=name,
                        description=desc,
                        component=loc_str,
                        severity=severity,
                        snippet=line_strip,
                        remediation=remediation,
                    )
                )

        # 3. Static Injection Risks
        for name, pattern, target_exts, severity, desc, remediation in INJECTION_PATTERNS:
            if suffix in target_exts and pattern.search(line):
                findings.append(
                    create_code_finding(
                        scope="Static Code Analysis",
                        title=name,
                        description=desc,
                        component=loc_str,
                        severity=severity,
                        snippet=line_strip,
                        remediation=remediation,
                    )
                )

    return findings


def query_osv_batch(dependencies: List[Tuple[str, str, str, str]]) -> List[Finding]:
    """Query the free OSV.dev vulnerability API for known package CVEs."""
    findings: List[Finding] = []
    if not dependencies:
        return findings

    session = requests.Session()

    for pkg_name, version, ecosystem, manifest_path in dependencies:
        try:
            payload = {
                "package": {"name": pkg_name, "ecosystem": ecosystem},
                "version": version,
            }
            resp = session.post("https://api.osv.dev/v1/query", json=payload, timeout=3)
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulns", [])
                for vuln in vulns:
                    vuln_id = vuln.get("id", "VULN")
                    summary = vuln.get("summary") or vuln.get("details") or "Known security vulnerability"
                    aliases = ", ".join(vuln.get("aliases", []))
                    if aliases:
                        summary += f" ({aliases})"

                    findings.append(
                        create_code_finding(
                            scope="Dependency Vulnerabilities",
                            title=f"Vulnerable Dependency: {pkg_name} {version} ({vuln_id})",
                            description=f"Package {pkg_name} {version} is affected by {vuln_id}: {summary[:200]}",
                            component=f"{manifest_path} ({pkg_name}=={version})",
                            severity="High",
                            snippet=f"{pkg_name}=={version}\nOSV ID: {vuln_id}\nAliases: {aliases}",
                            remediation=f"Upgrade {pkg_name} to a secure, non-vulnerable version.",
                        )
                    )
        except Exception:
            # Continue gracefully on offline/sandboxed execution without crashing
            pass

    return findings


def parse_manifests(root_dir: Path) -> Tuple[List[Tuple[str, str, str, str]], bool]:
    """Detect and parse dependency manifests across Python, Node, Java, Go, Ruby, PHP."""
    dependencies: List[Tuple[str, str, str, str]] = []
    manifest_found = False

    # 1. requirements.txt
    for req_file in root_dir.glob("**/requirements*.txt"):
        if should_skip_path(req_file, root_dir, set()):
            continue
        manifest_found = True
        try:
            for line in req_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip().split("#")[0].strip()
                if "==" in line:
                    parts = line.split("==")
                    if len(parts) == 2:
                        rel_p = str(req_file.relative_to(root_dir))
                        dependencies.append((parts[0].strip(), parts[1].strip(), "PyPI", rel_p))
        except Exception:
            pass

    # 2. package.json / package-lock.json
    for pkg_json in root_dir.glob("**/package.json"):
        if should_skip_path(pkg_json, root_dir, set()):
            continue
        manifest_found = True
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            for name, ver in deps.items():
                clean_ver = re.sub(r"^[^\d]*", "", str(ver))
                if clean_ver:
                    dependencies.append((name, clean_ver, "npm", str(pkg_json.relative_to(root_dir))))
        except Exception:
            pass

    # 3. go.mod
    for go_mod in root_dir.glob("**/go.mod"):
        if should_skip_path(go_mod, root_dir, set()):
            continue
        manifest_found = True
        try:
            for line in go_mod.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                match = re.match(r"^require\s+([^\s]+)\s+v?([0-9\.]+)", line)
                if match:
                    dependencies.append((match.group(1), match.group(2), "Go", str(go_mod.relative_to(root_dir))))
        except Exception:
            pass

    # 4. Gemfile.lock
    for gem_lock in root_dir.glob("**/Gemfile.lock"):
        if should_skip_path(gem_lock, root_dir, set()):
            continue
        manifest_found = True
        try:
            for line in gem_lock.read_text(encoding="utf-8", errors="ignore").splitlines():
                match = re.match(r"^\s{4}([a-zA-Z0-9_\-]+)\s+\(([0-9\.]+)\)", line)
                if match:
                    rel_p = str(gem_lock.relative_to(root_dir))
                    dependencies.append((match.group(1), match.group(2), "RubyGems", rel_p))
        except Exception:
            pass

    # 5. composer.json
    for comp_json in root_dir.glob("**/composer.json"):
        if should_skip_path(comp_json, root_dir, set()):
            continue
        manifest_found = True
        try:
            data = json.loads(comp_json.read_text(encoding="utf-8", errors="ignore"))
            deps = {**data.get("require", {}), **data.get("require-dev", {})}
            for name, ver in deps.items():
                clean_ver = re.sub(r"^[^\d]*", "", str(ver))
                if clean_ver and "/" in name:
                    dependencies.append((name, clean_ver, "Packagist", str(comp_json.relative_to(root_dir))))
        except Exception:
            pass

    return dependencies, manifest_found


def run_local_scan(
    target_path: str,
    progress: Callable[[str], None] = lambda _: None,
) -> List[Finding]:
    """Execute language-agnostic security assessment over a local folder or file."""
    root = Path(target_path).resolve()
    findings: List[Finding] = []

    if not root.exists():
        return findings

    progress("Collecting files and manifests")
    custom_ignored = parse_gitignore(root if root.is_dir() else root.parent)

    files_to_scan: List[Path] = []
    if root.is_file():
        files_to_scan.append(root)
        base_dir = root.parent
    else:
        base_dir = root
        for p in root.rglob("*"):
            if p.is_dir():
                continue
            if should_skip_path(p, base_dir, custom_ignored):
                continue
            files_to_scan.append(p)

    progress(f"Analyzing filesystem & {len(files_to_scan)} files")

    for file_path in files_to_scan:
        rel_str = str(file_path.relative_to(base_dir))
        file_name = file_path.name

        # a) Exposed Sensitive Files
        if file_name in SENSITIVE_FILENAMES:
            sev, desc = SENSITIVE_FILENAMES[file_name]
            findings.append(
                create_code_finding(
                    scope="Sensitive File Exposure",
                    title=f"Exposed Sensitive File: {file_name}",
                    description=desc,
                    component=rel_str,
                    severity=sev,
                    snippet=f"File present at: {rel_str}",
                    remediation="Add file to .gitignore and rotate any contained secrets.",
                )
            )

        ext = file_path.suffix.lower()
        if ext in SENSITIVE_FILE_EXTENSIONS:
            sev, desc = SENSITIVE_FILE_EXTENSIONS[ext]
            findings.append(
                create_code_finding(
                    scope="Sensitive File Exposure",
                    title=f"Sensitive Key / Data File ({ext})",
                    description=desc,
                    component=rel_str,
                    severity=sev,
                    snippet=f"File present at: {rel_str}",
                    remediation="Avoid committing private key or database dump files into source control.",
                )
            )

        # Skip large files and binary files for content checks
        try:
            if file_path.stat().st_size > MAX_FILE_SIZE_BYTES or is_binary_file(file_path):
                continue
        except Exception:
            continue

        # b) Code contents check (secrets, insecure config, static injection)
        findings.extend(check_file_contents(file_path, rel_str))

    # c) Dependency vulnerability checks via OSV.dev
    progress("Checking dependencies against OSV.dev database")
    dependencies, manifest_found = parse_manifests(base_dir)
    if dependencies:
        findings.extend(query_osv_batch(dependencies))
    elif not manifest_found:
        findings.append(
            create_code_finding(
                scope="Dependency Vulnerabilities",
                title="No Dependency Manifests Found",
                description="No supported package manifests (requirements.txt, package.json, etc.) were found.",
                component=str(base_dir),
                severity="Info",
                snippet="Dependency vulnerability scan skipped.",
                remediation="Ensure project dependencies are declared in standard package manifests.",
            )
        )

    return findings
