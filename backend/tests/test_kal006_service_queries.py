"""KAL-006 — bounded queries from recon asset lines."""

from src.recon.service_version_queries import bounded_service_queries_from_assets


def test_bounded_queries_dedupes_and_caps():
    assets = [
        "10.0.0.1:443 open tcp 443 https nginx 1.18",
        "10.0.0.2:443 open tcp 443 https nginx 1.18",
        "192.168.1.1:80 open tcp 80 http Apache httpd 2.4.41",
    ]
    q = bounded_service_queries_from_assets(assets, max_queries=2)
    assert len(q) == 2
    assert any("nginx" in x.lower() for x in q)


def test_bounded_queries_empty_assets():
    assert bounded_service_queries_from_assets([], max_queries=5) == []
