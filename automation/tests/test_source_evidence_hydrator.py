from automation.content_discovery import DiscoveredArticle
from automation import source_evidence_hydrator as hydration


def _article(url="https://publisher.example/report"):
    return DiscoveredArticle(
        url=url,
        title="Threat report",
        summary="short preview",
        published_at="2026-10-02T10:00:00+00:00",
        content_hash="abc",
        labels=["Threat Intelligence"],
        source="global_rss",
        full_content="short preview",
        source_publisher="Example Research",
    )


def test_private_and_special_destinations_are_rejected_without_http():
    assert hydration._validate_public_destination("http://127.0.0.1/a") is False
    assert hydration._validate_public_destination("http://169.254.169.254/a") is False
    assert hydration._validate_public_destination("http://localhost/a") is False
    assert hydration._validate_public_destination("file:///etc/passwd") is False


def test_public_dns_destination_requires_only_global_addresses(monkeypatch):
    monkeypatch.setattr(
        hydration.socket,
        "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 443))],
    )
    assert hydration._validate_public_destination("https://publisher.example/report") is True

    monkeypatch.setattr(
        hydration.socket,
        "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("10.0.0.7", 443))],
    )
    assert hydration._validate_public_destination("https://publisher.example/report") is False


def test_selected_rss_hydration_adopts_only_materially_richer_source(monkeypatch):
    article = _article()
    rich = "<html><body><article>" + " ".join(
        f"<p>Evidence paragraph {i} contains source-backed technical context and validation detail.</p>"
        for i in range(180)
    ) + "</article></body></html>"

    monkeypatch.setattr(hydration, "_bounded_get_html", lambda url: rich)
    result = hydration.hydrate_selected_article(article)

    assert result.attempted is True
    assert result.adopted is True
    assert result.after_words > result.before_words + hydration.MIN_RICHER_WORD_GAIN
    assert "Evidence Capture: publisher article page" in article.full_content


def test_non_global_rss_is_never_hydrated(monkeypatch):
    article = _article()
    article.source = "cisa_kev"
    monkeypatch.setattr(
        hydration,
        "_bounded_get_html",
        lambda url: (_ for _ in ()).throw(AssertionError("must not fetch")),
    )

    result = hydration.hydrate_selected_article(article)
    assert result.attempted is False
    assert result.adopted is False


class _Response:
    status_code = 200
    headers = {"Content-Type": "text/html; charset=utf-8"}
    encoding = "utf-8"

    def __init__(self, body: bytes):
        self._body = body
        self.closed = False

    def iter_content(self, chunk_size=16384):
        yield self._body

    def close(self):
        self.closed = True


def test_response_body_is_hard_bounded(monkeypatch):
    monkeypatch.setattr(hydration, "_validate_public_destination", lambda url: True)
    response = _Response(b"x" * (hydration.MAX_RESPONSE_BYTES + 50_000))
    monkeypatch.setattr(hydration.requests, "get", lambda *a, **k: response)

    html = hydration._bounded_get_html("https://publisher.example/report")
    assert html is not None
    assert len(html.encode("utf-8")) == hydration.MAX_RESPONSE_BYTES
    assert response.closed is True
