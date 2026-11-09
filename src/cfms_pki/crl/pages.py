"""Generate static HTML distribution pages for Certificate Revocation Lists."""

import hashlib
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import (
    BaseLoader,
    ChoiceLoader,
    Environment,
    FileSystemLoader,
    PackageLoader,
    select_autoescape,
)


@dataclass(frozen=True)
class CRLFileInfo:
    name: str
    path: Path
    size_bytes: int
    sha256: str

    @property
    def formatted_size(self) -> str:
        return f"{self.size_bytes:,} B"


def scan_crl_files(crl_dir: Path) -> list[CRLFileInfo]:
    """Scan a directory for .crl files and compute their metadata."""
    if not crl_dir.exists():
        return []
    files = sorted(crl_dir.glob("*.crl"))
    result: list[CRLFileInfo] = []
    for p in files:
        data = p.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        result.append(
            CRLFileInfo(
                name=p.name,
                path=p,
                size_bytes=len(data),
                sha256=sha256,
            )
        )
    return result


def get_template_environment(template_dir: Path | None = None) -> Environment:
    """Create a Jinja2 Environment with optional custom template override."""
    loaders: list[BaseLoader] = []
    if template_dir and template_dir.exists():
        loaders.append(FileSystemLoader(template_dir))
    loaders.append(PackageLoader("cfms_pki", "templates"))
    return Environment(
        loader=ChoiceLoader(loaders),
        autoescape=select_autoescape(["html", "xml"]),
    )


def build_crl_pages(
    crl_dir: Path = Path("crl"),
    output_dir: Path = Path("_site"),
    template_dir: Path | None = None,
    generated_at: str | None = None,
    copy_crls: bool = True,
) -> None:
    """Build the GitHub Pages distribution site for CRLs.

    Copies .crl files to `<output_dir>/crl/`, creates `.nojekyll`,
    and generates root `index.html` and `crl/index.html`.
    """
    output_dir = Path(output_dir)
    output_crl_dir = output_dir / "crl"
    output_crl_dir.mkdir(parents=True, exist_ok=True)

    # Prevent GitHub Pages from ignoring files prefixed with underscores or Jekyll defaults
    (output_dir / ".nojekyll").touch()

    # Copy CRLs if requested
    if copy_crls and crl_dir.exists():
        for crl_path in crl_dir.glob("*.crl"):
            dest = output_crl_dir / crl_path.name
            if dest.resolve() != crl_path.resolve():
                shutil.copy2(crl_path, dest)

    # Scan CRL files from the output distribution directory
    crl_files = scan_crl_files(output_crl_dir)
    if not crl_files and crl_dir.exists():
        crl_files = scan_crl_files(crl_dir)

    now_utc = generated_at or datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

    env = get_template_environment(template_dir)
    template = env.get_template("index.html")

    # Keep file metadata available to custom homepage templates.
    root_crls = [
        {
            "name": f.name,
            "size": f.formatted_size,
            "sha256": f.sha256,
            "href": f"crl/{f.name}",
        }
        for f in crl_files
    ]
    root_html = template.render(
        title="CFMS PKI — Certificate Information",
        desc="Certificate infrastructure, automated issuance and revocation list distribution for the CFMS ecosystem.",
        crls=root_crls,
        is_crl_subdir=False,
        generated_at=now_utc,
    )
    (output_dir / "index.html").write_text(root_html, encoding="utf-8")

    # Render crl/index.html (links pointing to direct filename <name>)
    crl_crls = [
        {
            "name": f.name,
            "size": f.formatted_size,
            "sha256": f.sha256,
            "href": f.name,
        }
        for f in crl_files
    ]
    crl_html = env.get_template("crl.html").render(
        title="CFMS PKI CRL Directory",
        desc="Download published CFMS PKI certificate revocation lists and compare SHA-256 checksums.",
        crls=crl_crls,
        is_crl_subdir=True,
        generated_at=now_utc,
    )
    (output_crl_dir / "index.html").write_text(crl_html, encoding="utf-8")
