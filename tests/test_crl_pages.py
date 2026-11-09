"""Tests for static CRL Pages generation."""

import hashlib
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from cfms_pki.crl.pages import build_crl_pages, scan_crl_files


class Links(HTMLParser):
    def __init__(self, html: str) -> None:
        super().__init__()
        self.links: list[dict[str, str | None]] = []
        self.feed(html)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            self.links.append(dict(attrs))


def test_scan_crl_files_empty(tmp_path: Path) -> None:
    assert scan_crl_files(tmp_path / "nonexistent") == []
    assert scan_crl_files(tmp_path) == []


def test_scan_crl_files_with_content(tmp_path: Path) -> None:
    crl1 = tmp_path / "test-ca.crl"
    crl2 = tmp_path / "another-ca.crl"
    crl1.write_bytes(b"mock crl content 1")
    crl2.write_bytes(b"mock crl content 2")

    # Non-crl file should be ignored
    (tmp_path / "ignored.txt").write_text("ignore me")

    results = scan_crl_files(tmp_path)
    assert len(results) == 2
    assert results[0].name == "another-ca.crl"
    assert results[0].size_bytes == len(b"mock crl content 2")
    assert results[0].formatted_size == f"{len(b'mock crl content 2'):,} B"
    assert results[0].sha256 == hashlib.sha256(b"mock crl content 2").hexdigest()

    assert results[1].name == "test-ca.crl"
    assert results[1].size_bytes == len(b"mock crl content 1")
    assert results[1].sha256 == hashlib.sha256(b"mock crl content 1").hexdigest()


def test_build_crl_pages_with_files(tmp_path: Path) -> None:
    crl_dir = tmp_path / "crl"
    crl_dir.mkdir()
    crl_file = crl_dir / "generic-intermediate.crl"
    content = b"sample crl bytes for test"
    crl_file.write_bytes(content)
    expected_hash = hashlib.sha256(content).hexdigest()

    out_dir = tmp_path / "_site"
    build_crl_pages(
        crl_dir=crl_dir, output_dir=out_dir, generated_at="2026-11-04 12:00:00 UTC"
    )

    # Verify CRL file was copied
    assert (out_dir / "crl" / "generic-intermediate.crl").read_bytes() == content

    # Check root page
    root_html = (out_dir / "index.html").read_text(encoding="utf-8")
    assert 'href="crl/"' in root_html
    assert "generic-intermediate.crl" not in root_html
    assert "<table>" not in root_html

    # Check crl page
    crl_html = (out_dir / "crl" / "index.html").read_text(encoding="utf-8")
    assert 'href="generic-intermediate.crl"' in crl_html
    assert expected_hash in crl_html
    assert f"{len(content):,} B" in crl_html
    assert "download" in crl_html
    assert "Generated at: 2026-11-04 12:00:00 UTC" in crl_html


def test_build_crl_pages_custom_template(tmp_path: Path) -> None:
    crl_dir = tmp_path / "crl"
    crl_dir.mkdir()
    (crl_dir / "test.crl").write_bytes(b"content")

    custom_templates = tmp_path / "custom_tpl"
    custom_templates.mkdir()
    (custom_templates / "base.html").write_text(
        "CUSTOM BASE: {% block content %}{% endblock %}", encoding="utf-8"
    )
    (custom_templates / "index.html").write_text(
        '{% extends "base.html" %}{% block content %}CUSTOM CONTENT FOR {{ title }}{% endblock %}',
        encoding="utf-8",
    )

    out_dir = tmp_path / "_site"
    build_crl_pages(
        crl_dir=crl_dir,
        output_dir=out_dir,
        template_dir=custom_templates,
    )

    root_html = (out_dir / "index.html").read_text(encoding="utf-8")
    assert (
        "CUSTOM BASE: CUSTOM CONTENT FOR CFMS PKI — Certificate Information"
        in root_html
    )
    # The packaged directory template also inherits a custom base.
    crl_html = (out_dir / "crl" / "index.html").read_text(encoding="utf-8")
    assert "CUSTOM BASE:" in crl_html
    assert 'href="test.crl"' in crl_html

    (custom_templates / "crl.html").write_text(
        "CUSTOM DIRECTORY: {{ crls[0].href }}", encoding="utf-8"
    )
    build_crl_pages(crl_dir=crl_dir, output_dir=out_dir, template_dir=custom_templates)
    assert (out_dir / "crl" / "index.html").read_text(encoding="utf-8") == (
        "CUSTOM DIRECTORY: test.crl"
    )


def test_bilingual_navigation_and_project_prefix(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "team&ca.crl").write_bytes(b"original published bytes")
    output = tmp_path / "site"
    build_crl_pages(crl_dir=source, output_dir=output)
    origin = "https://distribution.example/pki/"
    for page, current, switch in (
        ("index.html", 1, "zh-cn/"),
        ("crl/index.html", 2, "zh-cn/crl/"),
        ("zh-cn/index.html", 1, ""),
        ("zh-cn/crl/index.html", 2, "crl/"),
    ):
        html = (output / page).read_text(encoding="utf-8")
        chinese = page.startswith("zh-cn/")
        prefix = "zh-cn/" if chinese else ""
        links = Links(html).links
        base = urljoin(origin, page)
        expected = [
            origin + prefix,
            origin + prefix,
            origin + prefix + "crl/",
            "https://acme.cfms-pki.crpteam.club/" + prefix,
            "https://github.com/cfms-dev/pki",
            origin + switch,
        ]
        assert [urljoin(base, link["href"]) for link in links[:6]] == expected
        assert links[current]["aria-current"] == "page"
        assert sum(link.get("aria-current") == "page" for link in links[:6]) == 1
        assert f'<html lang="{"zh-CN" if chinese else "en"}">' in html
        assert links[5]["hreflang"] == ("en" if chinese else "zh-CN")
        assert "<script" not in html
        assert "{{" not in html
        # Resolve every site-local link as if served under /pki/.
        for link in links:
            url = urlsplit(urljoin(base, link["href"]))
            if url.netloc != "distribution.example":
                continue
            assert url.path.startswith("/pki/")
            target = output / url.path.removeprefix("/pki/")
            if url.path.endswith("/"):
                target /= "index.html"
            assert target.is_file(), link
        if current == 2:
            assert "team&amp;ca.crl" in html
            download = next(link for link in links if "download" in link)
            assert urljoin(base, download["href"]) == origin + "crl/team&ca.crl"
    assert list(output.rglob("*.crl")) == [output / "crl/team&ca.crl"]
    assert (output / "crl/team&ca.crl").read_bytes() == b"original published bytes"


def test_chinese_empty_directory(tmp_path: Path) -> None:
    build_crl_pages(crl_dir=tmp_path / "missing", output_dir=tmp_path / "site")
    html = (tmp_path / "site/zh-cn/crl/index.html").read_text(encoding="utf-8")
    assert "暂无可用的 CRL 文件。" in html
    assert "已发布的 CRL 文件" in html
