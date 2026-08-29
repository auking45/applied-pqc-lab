#!/usr/bin/env python3
"""
Applied PQC Lab - Automation & Verification Harness CLI (.harness/harness.py)
Provides:
  - 'new': Scaffold new bilingual technical articles & test skeletons
  - 'lint': Static rule checker verifying SKILL.md authoring compliance
  - 'test': Run Docker-based cryptographic verification & toolchain tests
"""

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_KO_DIR = REPO_ROOT / "docs" / "ko"
DOCS_EN_DIR = REPO_ROOT / "docs" / "en"
TEMPLATES_DIR = REPO_ROOT / ".harness" / "templates"


def log_info(msg: str):
    print(f"\033[0;34m[INFO]\033[0m {msg}")


def log_pass(msg: str):
    print(f"\033[0;32m[PASS]\033[0m {msg}")


def log_warn(msg: str):
    print(f"\033[0;33m[WARN]\033[0m {msg}")


def log_fail(msg: str):
    print(f"\033[0;31m[FAIL]\033[0m {msg}", file=sys.stderr)


# -----------------------------------------------------------------------------
# 1. Scaffolding ('new') Command
# -----------------------------------------------------------------------------
def cmd_new(args):
    chapter = args.chapter.strip()
    slug = args.slug.strip()
    title_ko = args.title_ko.strip()
    title_en = args.title_en.strip()
    desc_ko = getattr(args, "desc_ko", "").strip() or f"{title_ko} 메커니즘 및 실습 가이드."
    desc_en = getattr(args, "desc_en", "").strip() or f"{title_en} mechanisms and practical lab guide."

    log_info(f"Scaffolding new article: [{chapter}] {slug}")

    # Paths
    ko_target = DOCS_KO_DIR / chapter / f"{slug}.md"
    en_target = DOCS_EN_DIR / chapter / f"{slug}.md"

    ko_target.parent.mkdir(parents=True, exist_ok=True)
    en_target.parent.mkdir(parents=True, exist_ok=True)

    # Render templates (simple format replacement or jinja)
    try:
        from jinja2 import Template
        def render_tmpl(tmpl_path, **ctx):
            with open(tmpl_path, "r", encoding="utf-8") as f:
                return Template(f.read()).render(**ctx)
    except ImportError:
        def render_tmpl(tmpl_path, **ctx):
            with open(tmpl_path, "r", encoding="utf-8") as f:
                res = f.read()
                for k, v in ctx.items():
                    res = res.replace(f"{{{{ {k} }}}}", str(v))
                return res

    ko_content = render_tmpl(
        TEMPLATES_DIR / "doc_ko.md.j2",
        title_ko=title_ko,
        description_ko=desc_ko,
        slug=slug,
    )
    en_content = render_tmpl(
        TEMPLATES_DIR / "doc_en.md.j2",
        title_en=title_en,
        description_en=desc_en,
        slug=slug,
    )

    with open(ko_target, "w", encoding="utf-8") as f:
        f.write(ko_content)
    log_pass(f"Created Korean document: {ko_target.relative_to(REPO_ROOT)}")

    with open(en_target, "w", encoding="utf-8") as f:
        f.write(en_content)
    log_pass(f"Created English document: {en_target.relative_to(REPO_ROOT)}")

    # Create optional code skeletons
    if args.with_code:
        cpp_target = REPO_ROOT / "examples" / "cpp" / f"{slug}.cpp"
        rust_target = REPO_ROOT / "examples" / "rust" / f"{slug}.rs"
        sh_target = REPO_ROOT / "examples" / "scripts" / f"{slug}.sh"

        cpp_target.parent.mkdir(parents=True, exist_ok=True)
        rust_target.parent.mkdir(parents=True, exist_ok=True)
        sh_target.parent.mkdir(parents=True, exist_ok=True)

        cpp_content = render_tmpl(TEMPLATES_DIR / "example_cpp.cpp.j2", title_en=title_en, slug=slug)
        rust_content = render_tmpl(TEMPLATES_DIR / "example_rust.rs.j2", title_en=title_en, slug=slug)
        sh_content = render_tmpl(TEMPLATES_DIR / "example_script.sh.j2", title_en=title_en, slug=slug)

        with open(cpp_target, "w", encoding="utf-8") as f:
            f.write(cpp_content)
        with open(rust_target, "w", encoding="utf-8") as f:
            f.write(rust_content)
        with open(sh_target, "w", encoding="utf-8") as f:
            f.write(sh_content)
        os.chmod(sh_target, 0o755)

        log_pass(f"Created code skeletons in examples/ (C++, Rust, CLI)")

    print("")
    log_pass("Article scaffolding completed successfully!")


# -----------------------------------------------------------------------------
# 2. Static Linter ('lint') Command
# -----------------------------------------------------------------------------
FORBIDDEN_KO_PATTERNS = [
    (re.compile(r"[가-힣]+습니다(?=[\s\.\,\!\?]|\$)"), "존댓말(~습니다) 사용 금지 -> '~한다/다' 평서체 사용"),
    (re.compile(r"[가-힣]+합니다(?=[\s\.\,\!\?]|\$)"), "존댓말(~합니다) 사용 금지 -> '~한다' 평서체 사용"),
    (re.compile(r"[가-힣]+됩니다(?=[\s\.\,\!\?]|\$)"), "존댓말(~됩니다) 사용 금지 -> '~된다' 평서체 사용"),
    (re.compile(r"[가-힣]+입니다(?=[\s\.\,\!\?]|\$)"), "존댓말(~입니다) 사용 금지 -> '~이다/다' 평서체 사용"),
    (re.compile(r"[가-힣]+해요(?=[\s\.\,\!\?]|\$)"), "구어체(~해요) 사용 금지 -> 평서체 사용"),
]


def check_korean_tone(ko_file: Path) -> list:
    errors = []
    text = ko_file.read_text(encoding="utf-8")
    lines = text.splitlines()

    in_code_block = False
    for line_idx, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("```"):
            in_code_block = not in_code_block
            continue
        if in_code_block:
            continue

        for pattern, reason in FORBIDDEN_KO_PATTERNS:
            match = pattern.search(line)
            if match:
                errors.append(f"{ko_file.relative_to(REPO_ROOT)}:{line_idx}: '{match.group(0)}' -> {reason}")

    return errors


def check_visual_first(file_path: Path) -> list:
    errors = []
    text = file_path.read_text(encoding="utf-8")
    if "```mermaid" not in text:
        errors.append(f"{file_path.relative_to(REPO_ROOT)}: Missing Visual-First architecture diagram (```mermaid)")
    return errors


def check_bilingual_sync() -> list:
    errors = []
    ko_files = {p.relative_to(DOCS_KO_DIR) for p in DOCS_KO_DIR.rglob("*.md")}
    en_files = {p.relative_to(DOCS_EN_DIR) for p in DOCS_EN_DIR.rglob("*.md")}

    missing_in_en = ko_files - en_files
    missing_in_ko = en_files - ko_files

    for f in missing_in_en:
        errors.append(f"docs/en/{f} missing (exists in docs/ko/{f})")
    for f in missing_in_ko:
        errors.append(f"docs/ko/{f} missing (exists in docs/en/{f})")

    return errors


def cmd_lint(args):
    log_info("Starting Applied PQC Lab documentation static compliance check...")
    all_errors = []

    # 1. Bilingual synchronization check
    sync_errors = check_bilingual_sync()
    if sync_errors:
        for err in sync_errors:
            log_fail(f"[Sync Error] {err}")
        all_errors.extend(sync_errors)
    else:
        log_pass("Bilingual file mapping is 100% synchronized (docs/ko <-> docs/en)")

    # 2. Korean Tone & Style Check
    ko_md_files = list(DOCS_KO_DIR.rglob("*.md"))
    for kf in ko_md_files:
        tone_errors = check_korean_tone(kf)
        if tone_errors:
            for err in tone_errors:
                log_fail(f"[Tone Violation] {err}")
            all_errors.extend(tone_errors)

    if not any("Tone Violation" in str(e) for e in all_errors):
        log_pass("Korean documentation tone compliance (~한다/다 평서체) verified")

    # 3. Visual-First Mermaid Check
    for doc_file in list(DOCS_KO_DIR.rglob("*.md")) + list(DOCS_EN_DIR.rglob("*.md")):
        vf_errors = check_visual_first(doc_file)
        if vf_errors:
            for err in vf_errors:
                log_fail(f"[Visual-First Violation] {err}")
            all_errors.extend(vf_errors)

    if not any("Visual-First Violation" in str(e) for e in all_errors):
        log_pass("Visual-First diagrams verified in all articles")

    print("-" * 60)
    if all_errors:
        log_fail(f"Lint failed with {len(all_errors)} rule violation(s).")
        sys.exit(1)
    else:
        log_pass("All documentation files strictly comply with SKILL.md standards!")
        sys.exit(0)


# -----------------------------------------------------------------------------
# 3. Test Runner ('test') Command
# -----------------------------------------------------------------------------
def cmd_test(args):
    log_info("Executing Docker-based PQC toolchain & E2E verification...")
    run_docker_script = REPO_ROOT / "scripts" / "run_docker.sh"

    if run_docker_script.exists():
        res = subprocess.run([str(run_docker_script), "verify"], cwd=str(REPO_ROOT))
        sys.exit(res.returncode)
    else:
        res = subprocess.run(["docker", "compose", "run", "--rm", "lab", "./docker/verify_toolchain.sh"], cwd=str(REPO_ROOT))
        sys.exit(res.returncode)


# -----------------------------------------------------------------------------
# Main Entry Point
# -----------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Applied PQC Lab - Authoring & Verification Harness CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: new
    parser_new = subparsers.add_parser("new", help="Scaffold new bilingual article and code templates")
    parser_new.add_argument("--chapter", required=True, help="Chapter folder name (e.g., 01-classical-hybrid)")
    parser_new.add_argument("--slug", required=True, help="Article slug filename without extension (e.g., rsa-wrapping)")
    parser_new.add_argument("--title-ko", required=True, help="Article title in Korean")
    parser_new.add_argument("--title-en", required=True, help="Article title in English")
    parser_new.add_argument("--desc-ko", default="", help="Short description in Korean")
    parser_new.add_argument("--desc-en", default="", help="Short description in English")
    parser_new.add_argument("--with-code", action="store_true", help="Also scaffold C++, Rust, and CLI example skeletons")
    parser_new.set_defaults(func=cmd_new)

    # Subcommand: lint
    parser_lint = subparsers.add_parser("lint", help="Lint docs for SKILL.md compliance (Tone, Visual-First, Sync)")
    parser_lint.set_defaults(func=cmd_lint)

    # Subcommand: test
    parser_test = subparsers.add_parser("test", help="Run Docker toolchain and PQC verification tests")
    parser_test.set_defaults(func=cmd_test)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
