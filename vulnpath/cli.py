"""VulnPath AI — Command Line Interface.

Provides CLI commands to scan source files, invoke LLM analysis (placeholder),
validate security findings, and generate reports.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from vulnpath.report import (
    render_console_summary,
    render_json_report,
    render_markdown_report,
)
from vulnpath.scanner import scan_file


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
    """Configure and parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="vulnpath",
        description="VulnPath AI — Defensive Code-Security Scanner.",
    )
    parser.add_argument(
        "target",
        type=str,
        help="Path to the source file to analyze.",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["markdown", "json", "console"],
        default="markdown",
        help="Report output format (default: markdown).",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Output file path to save report (prints to stdout if omitted).",
    )
    parser.add_argument(
        "--prompt",
        "-p",
        type=str,
        default=None,
        help="Path to custom system prompt markdown file.",
    )
    return parser.parse_args(args)


def main(argv: list[str] | None = None) -> int:
    """CLI execution entrypoint."""
    args = parse_args(argv)
    target_path = Path(args.target)

    if not target_path.exists():
        sys.stderr.write(f"Error: Target file '{args.target}' does not exist.\n")
        return 1

    if not target_path.is_file():
        sys.stderr.write(f"Error: Target '{args.target}' is not a file.\n")
        return 1

    try:
        result = scan_file(
            file_path=target_path,
            system_prompt_path=args.prompt,
        )
    except Exception as err:
        sys.stderr.write(f"Scan error: {err}\n")
        return 1

    # Render formatted report
    if args.format == "json":
        output = render_json_report(result)
    elif args.format == "console":
        output = render_console_summary(result)
    else:
        output = render_markdown_report(result)

    # Save to file or write to stdout
    if args.output:
        out_file = Path(args.output)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(output, encoding="utf-8")
        print(f"Report successfully saved to: {args.output}")
    else:
        print(output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
