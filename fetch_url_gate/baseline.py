"""The rule the comparison is made against.

A rule on the raw URL text that denies the literals people think of first:
a file URL, "localhost", 127.0.0.1, [::1] and 0.0.0.0. I wrote it to match
the text rule Cogent describes in its post on policy engines for tool calls,
which denies those five and allows the rest. I have not seen their rule's code.
"""

from __future__ import annotations

import re

_TEXT_RULE = re.compile(r"^\s*file:|localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0", re.IGNORECASE)


def text_rule_allows(url: str) -> bool:
    return _TEXT_RULE.search(url) is None
