"""Vulnerability-family identity used to decide whether two findings share a root cause.

Different scanners (and different rules of one scanner) label the same weakness with different
CWE numbers or rule names, e.g. Semgrep tags ``tainted-sql-string`` as CWE-704 although it is a
SQL-injection sink.  ``vulnerability_family`` maps CWEs, rule ids and titles to one stable name.
"""

from __future__ import annotations

import re

_FAMILY_BY_CWE = {
    "89": "sql_injection", "564": "sql_injection", "943": "sql_injection",
    "79": "xss", "80": "xss", "83": "xss", "87": "xss",
    "78": "command_injection", "77": "command_injection", "88": "command_injection", "94": "code_injection",
    "22": "path_traversal", "23": "path_traversal", "36": "path_traversal", "73": "path_traversal",
    "918": "ssrf", "601": "open_redirect", "352": "csrf", "502": "deserialization",
    "798": "hardcoded_secret", "259": "hardcoded_secret", "321": "hardcoded_secret",
}

# Ordered: first match wins.  Applied to "rule id + title" when no declared CWE maps to a family.
_TEXT_FAMILIES = (
    ("sql_injection", ("sql injection", "sql-injection", "sql_injection", "tainted-sql", "sql string", "sql-string")),
    ("xss", ("xss", "cross-site scripting", "reflective-xss", "raw-html", "raw html", "html-format",
             "directly-returned-format-string", "directly returned format string")),
    ("command_injection", ("command injection", "command-line-injection", "subprocess", "shell injection",
                           "os-system", "shell-true")),
    ("path_traversal", ("path traversal", "directory traversal", "path-injection")),
    ("ssrf", ("ssrf", "server-side request forgery")),
    ("deserialization", ("deserializ", "pickle", "yaml-load")),
)

_CWE_NUMBER = re.compile(r"(\d+)")


def _cwe_numbers(cwes: tuple[str, ...] | list[str]) -> list[str]:
    numbers = []
    for value in cwes:
        match = _CWE_NUMBER.search(str(value))
        if match:
            numbers.append(str(int(match.group(1))))
    return numbers


def vulnerability_family(cwes: tuple[str, ...] | list[str], text: str) -> str:
    """Stable family name, or ``cwe-<n>`` for an unmapped declared CWE, or ``unknown``."""
    numbers = _cwe_numbers(cwes)
    for number in numbers:
        if number in _FAMILY_BY_CWE:
            return _FAMILY_BY_CWE[number]
    lowered = text.casefold().replace("\u2011", "-")
    for family, needles in _TEXT_FAMILIES:
        if any(needle in lowered for needle in needles):
            return family
    return f"cwe-{numbers[0]}" if numbers else "unknown"
