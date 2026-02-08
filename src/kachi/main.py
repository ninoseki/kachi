from pathlib import Path
from urllib.parse import urlparse

from .schemas import RuleSet

base_rule_directory = Path(__file__).parent / "rules"


def unsafe_link(url: str, *, rule_set: RuleSet | None = None) -> str | None:
    """Make a (protected) link unsafe.

    Args:
        url (str): URL
        rule_set (RuleSet | None, optional): Rule set to use. If None, load from the built-in rule directory. Defaults to None.

    Returns:
        str | None: Unsafe link or None if no rule matched.
    """
    rule_set = rule_set or RuleSet.from_directory(base_rule_directory)
    return rule_set.call(url)


def is_protected_link(url: str, *, rule_set: RuleSet | None = None) -> bool:
    """Check if the link is a protected link.

    Args:
        url (str): URL
        rule_set (RuleSet | None, optional): Rule set to use. If None, load from the built-in rule directory. Defaults to None.
    Returns:
        bool: True if the link is a protected link, False otherwise.
    """
    rule_set = rule_set or RuleSet.from_directory(base_rule_directory)
    # do quick check whether it's a protected link (= supported by any of the rules)
    parsed = urlparse(url)
    return any(rule.filter.matches(url, parsed=parsed) for rule in rule_set.rules)
