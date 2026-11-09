"""Tests for static CRL Pages generation."""

import hashlib
from pathlib import Path

from cfms_pki.crl.pages import build_crl_pages, scan_crl_files


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
