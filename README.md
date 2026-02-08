# kachi

[![PyPI version](https://badge.fury.io/py/kachi.svg)](https://badge.fury.io/py/kachi)
[![Test](https://github.com/ninoseki/kachi/actions/workflows/test.yml/badge.svg)](https://github.com/ninoseki/kachi/actions/workflows/test.yml)

Make a protected link unsafe.

## Requirements

- Python 3.10+

## Installation

```bash
pip install kachi
```

## Usage

```python
from kachi import unsafe_link

result = unsafe_link("https://nam01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fexample.com")
print(result)  # https://example.com
```

### Bundled Rules

| Rule             | Service                    |
| ---------------- | -------------------------- |
| `azure_email`    | Azure Email Safe Links     |
| `barracuda`      | Barracuda Link Protect     |
| `esvalabs`       | EsvaLabs URL Sandbox       |
| `fireeye`        | FireEye URL Defense        |
| `o365_safelinks` | Microsoft 365 Safe Links   |
| `proofpoint_v1`  | Proofpoint URL Defense v1  |
| `proofpoint_v2`  | Proofpoint URL Defense v2  |
| `ses_awstrack`   | AWS SES Click Tracking     |
| `sophos`         | Sophos Email Protection    |
| `trendmicro`     | Trend Micro Email Security |
| `urldefense_v3`  | Proofpoint URL Defense v3  |
| `whatsapp`       | WhatsApp Link Redirect     |

## Rule Schema

Each rule is a YAML file with the following structure:

```yaml
name: example_rule
filter:
  hostname: example.com # exact match, or /regex/
  path: /redirect # optional, exact match or /regex/
pre_extract: # optional, transforms applied to URL before extraction
  - html_unescape
  - url_decode
extract:
  from: query_param # query_param, path_regex, or url_regex
  keys: [url, u] # for query_param: parameter names to try in order
  pattern: "/L0/(http[^/?#]+)" # for path_regex/url_regex: regex with capture group
  select: first # for query_param: first (default) or last
post_extract: # optional, transforms applied to extracted value
  - url_decode
```

### Filter

- `hostname` (required): string or list of strings. Exact match or `/regex/`.
- `path` (optional): string or list of strings. Exact match or `/regex/`.

### Extract Sources

| Source        | Description                                                            |
| ------------- | ---------------------------------------------------------------------- |
| `query_param` | Extract from URL query parameters. Requires `keys`.                    |
| `path_regex`  | Match regex against URL path. Requires `pattern` with a capture group. |
| `url_regex`   | Match regex against full URL. Requires `pattern` with a capture group. |

### Transforms

| Name                   | Description                                                      |
| ---------------------- | ---------------------------------------------------------------- |
| `html_unescape`        | Decode HTML entities (`&amp;` -> `&`)                            |
| `url_decode`           | Percent-decode (`%2F` -> `/`)                                    |
| `base64_decode`        | Base64 decode                                                    |
| `prepend`              | Prepend a string (requires a value, e.g. `{prepend: "http://"}`) |
| `proofpoint_v2_decode` | Decode Proofpoint v2 URL encoding                                |
