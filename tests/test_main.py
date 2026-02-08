import pytest

from kachi import is_protected_link, unsafe_link


@pytest.mark.parametrize(
    ("url", "rule_name"),
    [
        (
            "https://emails.azure.microsoft.com/redirect/?destination=http%3A%2F%2Fexample.com",
            "azure_email",
        ),
        (
            "https://linkprotect.cudasvc.com/?a=http%3A%2F%2Fexample.com",
            "barracuda",
        ),
        (
            "https://urlsand.esvalabs.com/?u=http%3A%2F%2Fexample.com",
            "esvalabs",
        ),
        (
            "https://protect2.fireeye.com/v1/url?k=abc&u=http%3A%2F%2Fexample.com",
            "fireeye",
        ),
        (
            "https://nam01.safelinks.protection.outlook.com/?url=http%3A%2F%2Fexample.com",
            "o365_safelinks",
        ),
        (
            "https://urldefense.proofpoint.com/v1/url?u=http://example.com&k=foo",
            "proofpoint_v1",
        ),
        (
            "https://urldefense.proofpoint.com/v2/url?u=http-3A__example.com&d=foo",
            "proofpoint_v2",
        ),
        (
            "https://abc.r.us-east-1.awstrack.me/L0/http%3A%2F%2Fexample.com/",
            "ses_awstrack",
        ),
        (
            "https://imsva91-ctp.trendmicro.com/wis/clicktime/v1/query?url=http%3A%2F%2Fexample.com",
            "trendmicro",
        ),
        (
            "https://urldefense.us/v3/__http://example.com__;!abc$",
            "urldefense_v3",
        ),
        (
            "https://l.wl.co/l?u=http%3A%2F%2Fexample.com",
            "whatsapp",
        ),
    ],
)
def test_unsafe_link(url: str, rule_name: str) -> None:
    result = unsafe_link(url)
    assert result == "http://example.com", (
        f"rule {rule_name!r}: expected http://example.com, got {result!r}"
    )


def test_unsafe_link_with_sophos() -> None:
    # ref. https://community.sophos.com/sophos-email/f/discussions/148123/get-effective-url-from-masqueraded-url
    result = unsafe_link(
        "https://eu-central-1.protection.sophos.com/?d=sophos.com&u=aHR0cHM6Ly93d3cuc29waG9zLmNvbS9kZS1kZS9wcm9kdWN0cy9zb3Bob3MtZW1haWw=&i=NjJkMTA1NzEwNWJkNDAxMDc5ZDliN2Uy&t=OGE0L3MwTUdrUmE0NXdkWEtxSzdGdUMxS0JsRDFlK2tmcThqK2FSQjBYQT0=&h=0d5a5f867dd841698a9ee6af8c1d8846&s=AVNPUEhUT0NFTkNSWVBUSVaP4zyKF4qdzGb8PYXRFY2poaAOWE20fUiquUBd3DxoZw"
    )
    assert result == "https://www.sophos.com/de-de/products/sophos-email"


def test_no_match() -> None:
    assert unsafe_link("http://example.com") is None


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (
            "https://emails.azure.microsoft.com/redirect/?destination=http%3A%2F%2Fexample.com",
            True,
        ),
        (
            "https://x.linkprotect.cudasvc.com/?a=http%3A%2F%2Fexample.com",
            True,
        ),
        (
            "https://urlsand.esvalabs.com/?u=http%3A%2F%2Fexample.com",
            True,
        ),
        (
            "https://protect2.fireeye.com/v1/url?k=abc&u=http%3A%2F%2Fexample.com",
            True,
        ),
        (
            "https://nam01.safelinks.protection.outlook.com/?url=http%3A%2F%2Fexample.com",
            True,
        ),
        (
            "https://urldefense.proofpoint.com/v1/url?u=http://example.com&k=foo",
            True,
        ),
        (
            "https://urldefense.proofpoint.com/v2/url?u=http-3A__example.com&d=foo",
            True,
        ),
        (
            "https://abc.r.us-east-1.awstrack.me/L0/http%3A%2F%2Fexample.com/",
            True,
        ),
        (
            "https://eu-central-1.protection.sophos.com/?d=example.com",
            True,
        ),
        (
            "https://imsva91.ctp.trendmicro.com/wis/clicktime/v1/query?url=http%3A%2F%2Fexample.com",
            True,
        ),
        (
            "https://urldefense.us/v3/__http://example.com__;!abc$",
            True,
        ),
        (
            "https://l.wl.co/l?u=http%3A%2F%2Fexample.com",
            True,
        ),
    ],
)
def test_is_protected_link(url: str, expected: bool) -> None:
    assert is_protected_link(url) is expected
