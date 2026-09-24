"""MCP tools for the community-spec framework."""

from __future__ import annotations

import re
from pathlib import Path

from darnit.core.logging import get_logger

logger = get_logger("darnit_csl.mcp_tools")

_PLACEHOLDER_RE = re.compile(
    r"(?i)(real name|real@email|example\.(com|org|net)|\bTODO\b|\bFIXME\b|\bTBD\b"
    r"|<name>|<email>|your name|firstname|lastname|insert name|name one|name two"
    r"|john doe|jane doe|_{5,}|\[Ideally list two different individuals)"
)


_MAILING_LIST_RE = re.compile(
    r"(?i)(@googlegroups\.com|@groups\.|@lists?\.|[._-]lists?@|listserv|majordomo"
    r"|\bno-?reply\b|@.*\.(?:groups|mailman)\b)"
)


def _looks_like_mailing_list(value: str) -> bool:
    """True if the contact is a group address rather than a named individual."""
    return bool(_MAILING_LIST_RE.search(value))


def _looks_like_placeholder(value: str) -> bool:
    """True if the value is empty or still looks like unfilled template text."""
    return not value.strip() or bool(_PLACEHOLDER_RE.search(value))


_URL_RE = re.compile(r"https?://")

_COC_CANDIDATES = (
    "CODE_OF_CONDUCT.md",
    "CODE-OF-CONDUCT.md",
    "code-of-conduct.md",
    "code_of_conduct.md",
    ".github/CODE_OF_CONDUCT.md",
    ".github/CODE-OF-CONDUCT.md",
    "docs/CODE_OF_CONDUCT.md",
    "docs/CODE-OF-CONDUCT.md",
)


def _find_existing_coc(repo: Path) -> str | None:
    """Relative path of an existing Code of Conduct file in the repo, if any."""
    for rel in _COC_CANDIDATES:
        if (repo / rel).is_file():
            return rel
    return None


_ORDER = ["CSL-01.01", "CSL-01.02", "CSL-02.01", "CSL-03.01", "CSL-04.01", "CSL-05.01"]


async def remediate_community_spec(
    local_path: str,
    scope: str = "",
    coc_contacts: str = "",
    code_license: str = "MIT",
    governance_mode: str = "csl",
    governance_reference: str = "",
    coc_policy: str = "csl",
    coc_reference: str = "",
    spec_name: str = "",
    add_readme_links: bool = True,
) -> str:
    """Write the Community Specification License (CSL 1.0) file set into a repo."""
    from darnit.config import load_framework_config
    from darnit.remediation.executor import RemediationExecutor
    from darnit.tools.audit import run_sieve_audit

    repo = Path(local_path).resolve()
    if not repo.exists():
        return f"Error: repository path not found: {repo}"

    coc_policy = (coc_policy or "csl").strip().lower()

    # Org-first: a project that already has a Code of Conduct (its own file,
    # an org community repo, or a foundation CoC such as CNCF / LF / JDF)
    # must point at it rather than naming individuals.
    existing_coc = _find_existing_coc(repo)
    if coc_policy != "org" and existing_coc:
        return (
            f"Error: this repository already has a Code of Conduct at "
            f"'{existing_coc}'. Re-run with coc_policy='org' and coc_reference "
            "set to one markdown sentence linking that document. Nothing was "
            "written."
        )

    if coc_policy == "org":
        if _looks_like_placeholder(coc_reference) or not _URL_RE.search(coc_reference):
            return (
                "Error: coc_policy='org' requires coc_reference: one markdown "
                "sentence linking the project's existing Code of Conduct (the "
                "repo's own file, the org's community repo, or a foundation "
                "CoC such as CNCF / LF / JDF). Check those locations first; "
                "only fall back to named individuals when no such CoC exists. "
                "Nothing was written."
            )
        # The linked CoC defines the reporting procedure; no inline contacts.
        coc_contacts = ""
    else:
        if _looks_like_placeholder(coc_contacts):
            return (
                f"Error: coc_contacts looks like a placeholder ({coc_contacts!r}). "
                "CSL requires a real Code of Conduct contact, ideally two named "
                "individuals with emails. Nothing was written."
            )

        if _looks_like_mailing_list(coc_contacts):
            return (
                f"Error: coc_contacts is a group address ({coc_contacts!r}). CSL asks "
                "for named individuals rather than a generic mailing list, so that "
                "someone filing a complaint knows exactly who receives it. Ask the "
                "project who should be listed. Nothing was written."
            )

    # The csl_scope template supplies the "# Scope" heading and the closing
    # "Any changes of Scope are not retroactive." line. A caller that drafts a
    # full scope document will include both, so strip them here rather than
    # emitting each one twice.
    scope = re.sub(r"\A#\s*Scope\s*\n+", "", scope.strip())
    scope = re.sub(
        r"\n*Any changes of Scope are not retroactive\.\s*\Z", "", scope
    ).strip()

    fw_path = Path(__file__).parent / "community-spec.toml"
    fw = load_framework_config(fw_path)

    context_values = {
        "csl_spec_name": spec_name,
        "csl_working_group_scope": scope,
        "csl_coc_contacts": coc_contacts,
        "csl_code_license": code_license,
        "csl_governance_mode": governance_mode,
        "csl_governance_reference": governance_reference,
        "csl_coc_policy": coc_policy,
        "csl_coc_reference": coc_reference,
    }

    executor = RemediationExecutor(
        local_path=str(repo), owner="", repo="",
        templates=fw.templates, context_values=context_values,
        framework_path=str(fw_path),
    )

    written: list[str] = []
    errors: list[str] = []
    for cid in _ORDER:
        control = fw.controls.get(cid)
        if control is None or control.remediation is None:
            continue
        try:
            res = executor.execute(cid, control.remediation, dry_run=False)
            (written if res.success else errors).append(
                cid if res.success else f"{cid}: {res.message}"
            )
        except Exception as e:  # noqa: BLE001
            errors.append(f"{cid}: {e}")

    if add_readme_links:
        candidates = ["README.md", "README.rst", "readme.md", "Readme.md", "README.txt"]
        readme = next((repo / c for c in candidates if (repo / c).is_file()), None)
        created = readme is None
        if created:
            readme = repo / "README.md"
        text = "# Specification\n" if created else readme.read_text(encoding="utf-8")
        if "02-scope.md" not in text:
            if readme.suffix.lower() == ".rst":
                block = ("\nGovernance & Licensing\n----------------------\n\n"
                         "- `Scope <governance/02-scope.md>`_\n"
                         "- `Notices <governance/03-notices.md>`_\n"
                         "- `License <governance/04-license.md>`_\n"
                         "- `Governance <governance/05-governance.md>`_\n")
            else:
                block = ("\n## Governance & Licensing\n"
                         "- [Scope](governance/02-scope.md)\n"
                         "- [Notices](governance/03-notices.md)\n"
                         "- [License](governance/04-license.md)\n"
                         "- [Governance](governance/05-governance.md)\n")
            readme.write_text(text + block, encoding="utf-8")
            written.append(f"CSL-06.01 ({readme.name} links)")

    results, _ = run_sieve_audit(
        owner="", repo="", local_path=str(repo), default_branch="main",
        apply_user_config=False, framework_name="community-spec", stop_on_llm=False,
    )
    lines = [f"# CSL remediation for {repo.name}", "",
             f"Files written: {', '.join(written) if written else 'none'}"]
    if errors:
        lines += ["", "Errors:"] + [f"- {e}" for e in errors]
    lines += ["", "## Re-audit"]
    lines += [f"- {r.get('id')}: {r.get('status')}" for r in sorted(results, key=lambda r: r.get("id", ""))]
    return "\n".join(lines)
