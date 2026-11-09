"""Generate static HTML distribution pages for Certificate Revocation Lists."""

import hashlib
import json
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.resources import files
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
    and generates English and Simplified Chinese overview and directory pages.
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
    for locale in ("en", "zh-cn"):
        messages = json.loads(
            files("cfms_pki")
            .joinpath("templates", "web", locale, "messages.json")
            .read_text(encoding="utf-8")
        )
        prefix = "" if locale == "en" else "zh-cn/"
        acme_href = f"https://acme.cfms-pki.crpteam.club/{prefix}"
        for page, template_name, relative_path in (
            ("overview", "index.html", "index.html"),
            ("crl", "crl.html", "crl/index.html"),
        ):
            destination = output_dir / prefix / relative_path
            # Relative URLs preserve a GitHub Pages project prefix such as /pki/.
            site_root = "../" * (len(destination.relative_to(output_dir).parts) - 1)
            overview_href = f"{site_root}{prefix}" or "./"
            crl_href = f"{site_root}{prefix}crl/"
            alternate_prefix = "zh-cn/" if locale == "en" else ""
            alternate_page = "crl/" if page == "crl" else ""
            crls = [
                {
                    "name": f.name,
                    "size": f.formatted_size,
                    "sha256": f.sha256,
                    "href": (
                        f.name
                        if page == "crl" and locale == "en"
                        else f"{site_root}crl/{f.name}"
                    ),
                }
                for f in crl_files
            ]
            html = env.get_template(template_name).render(
                **messages,
                title=messages[f"{page}_title"],
                desc=messages[f"{page}_desc"],
                locale=locale,
                crls=crls,
                is_crl_subdir=page == "crl",
                generated_at=now_utc,
                overview_href=overview_href,
                crl_href=crl_href,
                acme_href=acme_href,
                switch_href=f"{site_root}{alternate_prefix}{alternate_page}",
                overview_current="page" if page == "overview" else "false",
                crl_current="page" if page == "crl" else "false",
                acme_current="false",
                overview_arrow="",
                crl_arrow="",
                acme_arrow="↗",
            )
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(html, encoding="utf-8")
