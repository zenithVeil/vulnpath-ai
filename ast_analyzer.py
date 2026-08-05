# ast_analyzer.py - AST-based vulnerability detection for Python source files
#
# Uses only the Python standard library (ast module).
# Detects vulnerabilities structurally rather than with regex, which
# reduces false positives and gives accurate line numbers.

import ast

# ---------------------------------------------------------------- metadata

VULN_META = {
    "sql_injection": {
        "cwe": "CWE-89",
        "severity": "Critical",
        "description": "SQL Injection: user input concatenated into SQL query",
        "fix": 'Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))',
        "impact": "Full database compromise, data theft, data modification",
    },
    "command_injection": {
        "cwe": "CWE-78",
        "severity": "Critical",
        "description": "Command Injection: user input used in a system command",
        "fix": 'Use the argument-list form: subprocess.run(["ls", user_input])',
        "impact": "Remote code execution, system compromise",
    },
    "dangerous_eval": {
        "cwe": "CWE-95",
        "severity": "High",
        "description": "Use of eval()/exec() with non-literal input",
        "fix": "Avoid eval/exec; use ast.literal_eval only for trusted data",
        "impact": "Arbitrary code execution",
    },
    "hardcoded_credentials": {
        "cwe": "CWE-798",
        "severity": "Critical",
        "description": "Hardcoded credentials (password/secret/token/api key) in code",
        "fix": "Load secrets from environment variables or a secrets manager",
        "impact": "Credential leakage and unauthorized access",
    },
    "weak_crypto": {
        "cwe": "CWE-327",
        "severity": "High",
        "description": "Use of a weak or legacy cryptographic algorithm",
        "fix": "Use Argon2/bcrypt for passwords and SHA-256+ for hashing",
        "impact": "Weakened security, easier brute-force attacks",
    },
    "insecure_deserialization": {
        "cwe": "CWE-502",
        "severity": "High",
        "description": "Deserialization of data with pickle",
        "fix": "Never unpickle untrusted data; use JSON or a safe format",
        "impact": "Remote code execution via crafted payloads",
    },
    "path_traversal": {
        "cwe": "CWE-22",
        "severity": "High",
        "description": "File path built from potentially untrusted input",
        "fix": "Resolve the path and verify it stays inside an allowed base directory",
        "impact": "Unauthorized file access, data disclosure",
    },
}

SECRET_NAME_PARTS = (
    "password", "passwd", "pwd", "api_key", "apikey", "secret",
    "token", "aws_access", "aws_secret", "private_key", "client_secret",
)

WEAK_CRYPTO = ("md5", "sha1", "des", "rc4", "crypt")

DANGEROUS_EVAL = ("eval", "exec")

# ----------------------------------------------------------------- visitor

class VulnVisitor(ast.NodeVisitor):
    """Collects vulnerability findings while walking a Python AST."""

    def __init__(self):
        self.findings = []

    def _add(self, node, vuln_type, confidence=0.9):
        meta = VULN_META[vuln_type]
        line = getattr(node, "lineno", 0)
        self.findings.append({
            "vulnerability_type": vuln_type,
            "cwe_id": meta["cwe"],
            "severity": meta["severity"],
            "line": line,
            "lines": [line],
            "confidence": confidence,
            "description": meta["description"],
            "suggestion": meta["fix"],
            "impact": meta["impact"],
        })

    @staticmethod
    def _is_dynamic_string(node):
        """True when a node produces a string built at runtime (f-string,
        %-format, concatenation) rather than a plain literal."""
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, (ast.Mod, ast.Add)):
                return True
        return False

    @staticmethod
    def _is_string_literal(node):
        return isinstance(node, ast.Constant) and isinstance(node.value, str)

    @staticmethod
    def _func_name(node):
        """Return 'module.attr' or bare name for a Call's func node."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = node.value
            if isinstance(base, ast.Name):
                return base.id + "." + node.attr
        return ""

    # ------------------------------------------------------------------
    # Call-based checks: executed after visiting children
    # ------------------------------------------------------------------
    def visit_Call(self, node):
        fname = self._func_name(node.func)

        # SQL injection: cursor.execute(f"..."), conn.execute(...), etc.
        if fname.endswith(("execute", "executemany", "executescript")):
            if node.args and self._is_dynamic_string(node.args[0]):
                self._add(node, "sql_injection", confidence=0.9)

        # Command injection: os.system / os.popen with a non-literal argument
        if fname in ("os.system", "os.popen"):
            if node.args and not self._is_string_literal(node.args[0]):
                self._add(node, "command_injection", confidence=0.85)

        # Command injection: subprocess.call / subprocess.run / subprocess.Popen
        if fname in ("subprocess.call", "subprocess.run", "subprocess.Popen"):
            if node.args:
                first = node.args[0]
                if isinstance(first, (ast.List, ast.Tuple)):
                    for elt in first.elts:
                        if self._is_dynamic_string(elt):
                            self._add(node, "command_injection", confidence=0.8)
                            break
                elif self._is_dynamic_string(first):
                    self._add(node, "command_injection", confidence=0.9)
            # subprocess.run(..., shell=True) is always risky
            if any(kw.arg == "shell" and isinstance(kw.value, ast.Constant)
                   and kw.value.value is True for kw in node.keywords):
                self._add(node, "command_injection", confidence=0.8)

        # eval / exec
        if fname in DANGEROUS_EVAL:
            if node.args:
                confidence = 0.8 if not self._is_string_literal(node.args[0]) else 0.6
                self._add(node, "dangerous_eval", confidence=confidence)

        # pickle.loads / pickle.load
        if fname in ("pickle.loads", "pickle.load"):
            self._add(node, "insecure_deserialization", confidence=0.9)

        # open(...) with a non-literal path -> path traversal candidate
        if fname == "open":
            if node.args and not self._is_string_literal(node.args[0]):
                self._add(node, "path_traversal", confidence=0.5)

        # weak crypto: hashlib.md5(...), sha1(...), crypt(...)
        if fname in WEAK_CRYPTO or fname.split(".")[-1] in WEAK_CRYPTO:
            self._add(node, "weak_crypto", confidence=0.85)

        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Assignment-based checks: hardcoded secrets
    # ------------------------------------------------------------------
    def visit_Assign(self, node):
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id.lower()
            if any(part in name for part in SECRET_NAME_PARTS):
                if self._is_string_literal(node.value):
                    self._add(node, "hardcoded_credentials", confidence=0.9)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if isinstance(node.target, ast.Name):
            name = node.target.id.lower()
            if any(part in name for part in SECRET_NAME_PARTS):
                if self._is_string_literal(node.value):
                    self._add(node, "hardcoded_credentials", confidence=0.9)
        self.generic_visit(node)


# ---------------------------------------------------------------- analyzer

def analyze_python_file(file_path):
    """Analyze a Python source file using AST analysis.

    Returns a list of finding dicts. On a syntax error or read error,
    returns a single warning finding instead of crashing.
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            source = fh.read()
    except OSError as exc:
        return [{
            "vulnerability_type": "read_error",
            "cwe_id": "N/A",
            "severity": "Low",
            "line": 0,
            "lines": [0],
            "confidence": 1.0,
            "description": f"Could not read file: {exc}",
            "suggestion": "Ensure the file exists and is readable",
            "impact": "Scan skipped",
        }]

    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [{
            "vulnerability_type": "syntax_error",
            "cwe_id": "N/A",
            "severity": "Low",
            "line": exc.lineno or 0,
            "lines": [exc.lineno or 0],
            "confidence": 1.0,
            "description": f"Syntax error in file: {exc.msg}",
            "suggestion": "Fix the syntax error before scanning",
            "impact": "File could not be parsed",
        }]

    visitor = VulnVisitor()
    visitor.visit(tree)
    return visitor.findings
