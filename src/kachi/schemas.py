from __future__ import annotations

import base64
import html
import re
from dataclasses import dataclass, field
from enum import Enum
from functools import cache
from pathlib import Path
from typing import Any
from urllib.parse import ParseResult, parse_qs, unquote, urlparse

import yaml


def _to_matchers(value: str | list[str]) -> list[Matcher]:
    if isinstance(value, str):
        return [Matcher(value)]
    return [Matcher(v) for v in value]


_VALID_TRANSFORM_NAMES = frozenset(
    {"html_unescape", "url_decode", "base64_decode", "prepend", "proofpoint_v2_decode"}
)
_PARAMETERIZED_TRANSFORMS = frozenset({"prepend"})
_PROOFPOINT_V2_RE = re.compile(r"-([0-9A-Fa-f]{2})")


class ExtractSource(Enum):
    QUERY_PARAM = "query_param"
    PATH_REGEX = "path_regex"
    URL_REGEX = "url_regex"


class ParamSelect(Enum):
    FIRST = "first"
    LAST = "last"


@dataclass
class Matcher:
    """A pattern that matches via exact string comparison or regex.

    Raw value from YAML: bare string = exact match, ``/pattern/`` = regex.
    """

    raw: str

    is_regex: bool = field(init=False)
    pattern: str = field(init=False)
    _compiled: re.Pattern[str] | None = field(init=False, default=None, repr=False)

    def __post_init__(self) -> None:
        if not self.raw:
            raise ValueError("matcher pattern must not be empty")

        self.is_regex = (
            len(self.raw) >= 2 and self.raw.startswith("/") and self.raw.endswith("/")
        )
        self.pattern = self.raw[1:-1] if self.is_regex else self.raw

        if self.is_regex:
            try:
                self._compiled = re.compile(self.pattern)
            except re.error as e:
                raise ValueError(f"invalid regex /{self.pattern}/: {e}") from e

    def matches(self, value: str) -> bool:
        if self._compiled is not None:
            return self._compiled.search(value) is not None

        return value == self.pattern


@dataclass
class Filter:
    hostname: list[Matcher]
    path: list[Matcher] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.hostname:
            raise ValueError("at least one hostname matcher is required")

    def matches(self, url: str, *, parsed: ParseResult | None = None) -> bool:
        parsed = parsed or urlparse(url)
        hostname = parsed.hostname or ""
        if not any(m.matches(hostname) for m in self.hostname):
            return False

        return not self.path or any(m.matches(parsed.path) for m in self.path)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Filter:
        return cls(
            hostname=_to_matchers(data["hostname"]),
            path=_to_matchers(data["path"]) if "path" in data else [],
        )


@dataclass
class Transform:
    name: str
    value: str | None = None

    def __post_init__(self) -> None:
        if self.name not in _VALID_TRANSFORM_NAMES:
            raise ValueError(
                f"unknown transform {self.name!r}, "
                f"must be one of {sorted(_VALID_TRANSFORM_NAMES)}"
            )

        if self.name in _PARAMETERIZED_TRANSFORMS and self.value is None:
            raise ValueError(f"transform {self.name!r} requires a value")

        if self.name not in _PARAMETERIZED_TRANSFORMS and self.value is not None:
            raise ValueError(f"transform {self.name!r} does not accept a value")

    def call(self, value: str) -> str:
        match self.name:
            case "html_unescape":
                return html.unescape(value)
            case "url_decode":
                return unquote(value)
            case "base64_decode":
                return base64.b64decode(value).decode()
            case "prepend":
                return self.value + value  # type: ignore[operator]
            case "proofpoint_v2_decode":
                decoded = _PROOFPOINT_V2_RE.sub(
                    lambda m: chr(int(m.group(1), 16)),
                    value,
                )
                return decoded.replace("_", "/")

        raise ValueError(f"unknown transform {self.name!r}")

    @classmethod
    def from_dict(cls, data: str | dict[str, Any]) -> Transform:
        if isinstance(data, str):
            return cls(name=data)

        name = next(iter(data))
        return cls(name=name, value=data[name])


@dataclass
class Extract:
    source: ExtractSource
    keys: list[str] = field(default_factory=list)
    pattern: str | None = None
    select: ParamSelect = ParamSelect.FIRST
    _compiled_pattern: re.Pattern[str] | None = field(
        init=False, default=None, repr=False
    )

    def __post_init__(self) -> None:
        match self.source:
            case ExtractSource.QUERY_PARAM:
                if not self.keys:
                    raise ValueError("'keys' is required when source is 'query_param'")

                if self.pattern is not None:
                    raise ValueError(
                        "'pattern' is not allowed when source is 'query_param'"
                    )
            case ExtractSource.PATH_REGEX | ExtractSource.URL_REGEX:
                if self.pattern is None:
                    raise ValueError(
                        f"'pattern' is required when source is '{self.source.value}'"
                    )

                if self.keys:
                    raise ValueError(
                        f"'keys' is not allowed when source is '{self.source.value}'"
                    )

                try:
                    self._compiled_pattern = re.compile(self.pattern)
                except re.error as e:
                    raise ValueError(f"invalid {self.source.value} pattern: {e}") from e

                if self._compiled_pattern.groups < 1:
                    raise ValueError(
                        f"{self.source.value} pattern must contain at least one capture group"
                    )

    def call(self, url: str, *, parsed: ParseResult | None = None) -> str | None:
        parsed = parsed or urlparse(url)
        match self.source:
            case ExtractSource.QUERY_PARAM:
                qs = parse_qs(parsed.query)
                for key in self.keys:
                    values = qs.get(key, [])
                    if values:
                        return (
                            values[0]
                            if self.select == ParamSelect.FIRST
                            else values[-1]
                        )
                return None
            case ExtractSource.PATH_REGEX:
                m = self._compiled_pattern.search(parsed.path)  # type: ignore[union-attr]
                return m.group(1) if m else None
            case ExtractSource.URL_REGEX:
                m = self._compiled_pattern.search(url)  # type: ignore[union-attr]
                return m.group(1) if m else None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Extract:
        source = ExtractSource(data["from"])
        keys = data.get("keys", [])
        pattern = data.get("pattern")

        select: ParamSelect = ParamSelect.FIRST
        if "select" in data:
            select = ParamSelect(data["select"])

        return cls(
            source=source,
            keys=keys,
            pattern=pattern,
            select=select,
        )


@dataclass
class Rule:
    name: str
    filter: Filter
    extract: Extract
    pre_extract: list[Transform] = field(default_factory=list)
    post_extract: list[Transform] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("rule name must not be empty")

    def call(self, url: str, *, parsed: ParseResult | None = None) -> str | None:
        parsed = parsed or urlparse(url)
        if not self.filter.matches(url, parsed=parsed):
            return None

        for t in self.pre_extract:
            url = t.call(url)

        result = self.extract.call(url, parsed=parsed if not self.pre_extract else None)
        if result is None:
            return None

        for t in self.post_extract:
            result = t.call(result)

        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Rule:
        name = data["name"]
        filter_ = Filter.from_dict(data["filter"])
        extract = Extract.from_dict(data["extract"])
        pre_extract = [Transform.from_dict(t) for t in data.get("pre_extract", [])]
        post_extract = [Transform.from_dict(t) for t in data.get("post_extract", [])]
        return cls(
            name=name,
            filter=filter_,
            extract=extract,
            pre_extract=pre_extract,
            post_extract=post_extract,
        )

    @staticmethod
    @cache
    def from_file(path: str | Path) -> Rule:
        data = yaml.safe_load(Path(path).read_text())
        return Rule.from_dict(data)


@dataclass
class RuleSet:
    rules: list[Rule]

    def __post_init__(self) -> None:
        if not self.rules:
            raise ValueError("at least one rule is required")

        names = [r.name for r in self.rules]
        duplicates = {n for n in names if names.count(n) > 1}
        if duplicates:
            raise ValueError(f"duplicate rule names: {sorted(duplicates)}")

    def call(self, url: str) -> str | None:
        parsed = urlparse(url)
        for rule in self.rules:
            result = rule.call(url, parsed=parsed)
            if result is not None:
                return result

        return None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RuleSet:
        return cls(rules=[Rule.from_dict(r) for r in data["rules"]])

    @staticmethod
    @cache
    def from_directory(directory: str | Path) -> RuleSet:
        path = Path(directory)
        rules = [Rule.from_file(f) for f in sorted(path.glob("*.yml"))]
        return RuleSet(rules=rules)
