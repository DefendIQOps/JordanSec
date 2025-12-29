import os
import sys
from typing import Optional, Dict, Any

import typer
from rich.console import Console
from rich.panel import Panel

from jordansc import __app__, __author__, __version__
from jordansc.core.banner import about_panel, big_logo

# Modules
from jordansc.modules.headers import audit_headers, score_headers
from jordansc.modules.tls import audit_tls, score_tls
from jordansc.modules.cookies import audit_cookies, score_cookies

# Reporting
from jordansc.reporting.export import save_json

# إذا عندك build_text_report شغال اتركه
from jordansc.reporting.text_report import build_text_report

app = typer.Typer(
    help="JordanSec CLI - Defensive Web Security Auditing",
    add_completion=False,
)
console = Console()


@app.command()
def about(
    lang: str = typer.Option("en", "--lang", "-l", help="Language: en/ar"),
):
    """Show JordanSec identity and information."""
    console.print(f"[green]{big_logo()}[/green]")
    console.print(about_panel(__app__, __author__, lang=lang))


@app.command()
def doctor():
    """Check runtime environment."""
    lines = [
        f"Application : {__app__}",
        f"Author      : {__author__}",
        f"Version     : {__version__}",
        f"Python      : {sys.version.split()[0]}",
        f"Platform    : {sys.platform}",
        f"CWD         : {os.getcwd()}",
    ]
    console.print(
        Panel(
            "\n".join(lines),
            title="[bold green]Environment Check[/bold green]",
            border_style="green",
            padding=(1, 2),
        )
    )


def _ensure_parent_dir(path: str) -> None:
    p = os.path.abspath(os.path.expanduser(path))
    parent = os.path.dirname(p)
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)


def _pack_result(module_name: str, score: int, grade: str, data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "module": module_name,
        "score": score,
        "grade": grade,
        "data": data,
    }


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL or domain (example.com)"),
    module: str = typer.Option("headers", "--module", "-m", help="Module: headers | tls | cookies | all"),
    timeout: int = typer.Option(10, "--timeout", "-t", help="Request timeout (seconds)"),
    insecure: bool = typer.Option(False, "--insecure", help="Disable TLS verification (NOT recommended)"),
    output_json: Optional[str] = typer.Option(None, "--json", help="Save JSON report to file"),
    output_txt: Optional[str] = typer.Option(None, "--txt", help="Save TEXT report to file"),
):
    """
    Run defensive audit scan.
    Modules:
      - headers: Security headers check
      - tls:     TLS/HTTPS checks
      - cookies: Cookie flags checks
      - all:     Run all modules and produce combined report
    """
    module = (module or "").strip().lower()
    allowed = {"headers", "tls", "cookies", "all"}
    if module not in allowed:
        console.print("[red]Unknown module.[/red] Available: headers, tls, cookies, all")
        raise typer.Exit(1)

    console.print(f"[cyan]Running {module} audit on {target}...[/cyan]")

    combined: Dict[str, Any] = {
        "app": __app__,
        "version": __version__,
        "author": __author__,
        "target": target,
        "modules": [],
    }

    # ---- HEADERS ----
    if module in {"headers", "all"}:
        res = audit_headers(target, timeout=timeout, verify_tls=not insecure)
        if getattr(res, "error", None):
            console.print(f"[red]HEADERS Error: {res.error}[/red]")
        else:
            score, grade = score_headers(res)
            combined["modules"].append(_pack_result("headers", score, grade, res.to_dict()))
            console.print(f"[green]✓ HEADERS done[/green]  Score: {score}/100  Grade: {grade}")

    # ---- TLS ----
    if module in {"tls", "all"}:
        res = audit_tls(target, timeout=timeout, verify_tls=not insecure)
        if getattr(res, "error", None):
            console.print(f"[red]TLS Error: {res.error}[/red]")
        else:
            score, grade = score_tls(res)
            combined["modules"].append(_pack_result("tls", score, grade, res.to_dict()))
            console.print(f"[green]✓ TLS done[/green]      Score: {score}/100  Grade: {grade}")

    # ---- COOKIES ----
    if module in {"cookies", "all"}:
        res = audit_cookies(target, timeout=timeout, verify_tls=not insecure)
        if getattr(res, "error", None):
            console.print(f"[red]COOKIES Error: {res.error}[/red]")
        else:
            score, grade = score_cookies(res)
            combined["modules"].append(_pack_result("cookies", score, grade, res.to_dict()))
            console.print(f"[green]✓ COOKIES done[/green]  Score: {score}/100  Grade: {grade}")

    # ---- Summary print ----
    console.print("\n[bold]Summary:[/bold]")
    for m in combined["modules"]:
        console.print(f" - {m['module'].upper()}: {m['score']}/100  Grade: {m['grade']}")

    # ---- Save JSON ----
    if output_json:
        _ensure_parent_dir(output_json)
        saved = save_json(combined, output_json)
        console.print(f"[green]✓ Saved JSON report to:[/green]\n{saved}")

    # ---- Save TEXT ----
    if output_txt:
        _ensure_parent_dir(output_txt)
        txt = build_text_report(combined)
        with open(output_txt, "w", encoding="utf-8") as f:
            f.write(txt)
        console.print(f"[green]✓ Saved TEXT report to:[/green]\n{os.path.abspath(output_txt)}")


if __name__ == "__main__":
    app()
