"""Detection signatures for quick fuzzer result validation.

Each category maps to a list of strings that, when found (case-insensitive)
in an HTTP response body, indicate a genuine vulnerability trigger rather
than a false positive. Special logic for SSTI (evaluated math) and XSS
(unencoded reflection) is handled in the fuzzer engine itself.
"""

from __future__ import annotations

from typing import Final

DETECTION_SIGNATURES: Final[dict[str, list[str]]] = {
    "sqli": [
        "sql syntax",
        "mysql_fetch",
        "syntax error",
        "unclosed quotation",
        "quoted string not properly terminated",
        "ora-",
        "pg_query",
        "microsoft ole db",
        "sqlite_",
        "db2 sql error",
        "warning: mysql",
        "you have an error in your sql",
        "supplied argument is not a valid mysql",
        "unterminated string literal",
        "unexpected token",
    ],
    "xss": [
        "<script>alert(1)</script>",
        "onerror=alert(1)",
        "onload=alert(1)",
        "ontoggle=alert(1)",
        "<img src=x onerror=",
        "<svg onload=",
        "<details open ontoggle=",
    ],
    "ssti": [
        "49",
        "343",
        "7777777",
    ],
    "path_traversal": [
        "root:x:",
        "[boot loader]",
        "win.ini",
        "/bin/bash",
        "daemon:x:",
        "/etc/passwd",
        "[extensions]",
    ],
    "command_injection": [
        "uid=0",
        "uid=1",
        "root:x:",
        "volume in drive",
        "directory of",
        "total 0",
    ],
    "xxe": [
        "root:x:",
        "/etc/passwd",
        "meta-data",
        "ami-id",
        "instance-id",
    ],
    "ssrf": [
        "ami-id",
        "instance-id",
        "iam/security-credentials",
        "169.254.169.254",
        "metadata.google.internal",
    ],
    "prompt_injection": [
        "system prompt",
        "api key",
        "maintenance mode",
        "developer mode",
        "my instructions are",
        "i am an ai",
        "as a language model",
        "i cannot",
        "i'm not able",
    ],
    "nosql": [
        "syntaxerror",
        "castererror",
        "invalid bson",
        "illegal operator",
    ],
    "open_redirect": [
        "evil.com",
    ],
}
