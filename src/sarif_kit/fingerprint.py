"""Stable fingerprints so GitHub can dedupe alerts across pushes.

GitHub matches alerts between runs by each result's ``partialFingerprints``. If those
change, every push closes the old alerts and opens "new" ones. So we hash only the parts
of a finding that hold still when unrelated code moves: the file path, the rule, and a
context string (the code snippet if the tool gave us one, otherwise the message). The line
number is left out on purpose.

When two findings hash the same (same file, rule and context, different lines), the builder
tells them apart with a stable per-group index, the way CodeQL does. The key is namespaced
rather than posing as GitHub's own ``primaryLocationLineHash``, so it can't clash with a
value GitHub computes itself.
"""

from __future__ import annotations

import hashlib

#: partialFingerprints key. Bump the version suffix only if the algorithm changes
#: (doing so re-opens every existing alert once).
FINGERPRINT_KEY = "sarifKit/v1"


def base_fingerprint(uri: str, rule_id: str, context: str | None) -> str:
    """Hash the stable identity of a finding (path + rule + context), without the line number."""
    h = hashlib.sha256()
    for part in (uri, rule_id, context or ""):
        h.update(part.encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()
