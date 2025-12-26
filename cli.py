import os
import sys
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel

from jordansc import __app__, __author__, __version__
from jordansc.core.banner import about_panel, big_logo
from jordansc.modules.headers import audit_headers, score_headers
from jordansc.reporting.export import save_json

app = typer.Typer(
    help="JordanSec CLI - Cybersecurity & Security Auditing",
    add_completion=False,
)
console = Console()


@app.command()
def about(
    lang: str = typer.Option("en", "--lang", "-l", help="Language: en/ar"),
):
    """
    Show JordanSec identity and information.
    """
    console.print(f"[green]{big_logo()}[/green]")
    console.print(about_panel(__app__, __author__, lang=lang))


@app.command()
def doctor():
    """
    Check runtime environment.
    """
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


@app.command()
def init(
    path: str = typer.Option(".", "--path", "-p", help="Project directory to initialize"),
):
    """
    Initialize JordanSec project structure.
    """
    folders = [
        "jordansc/core",
        "jordansc/modules",
        "jordansc/reporting",
        "configs",
    ]

    for f in folders:
        os.makedirs(os.path.join(path, f), exist_ok=True)

    # minimal package init files
    for p in [
        "jordansc/__init__.py",
        "jordansc/core/__init__.py",
        "jordansc/modules/__init__.py",
        "jordansc/reporting/__init__.py",
    ]:
        full = os.path.join(path, p)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        if not os.path.exists(full):
            with open(full, "w", encoding="utf-8") as fp:
                fp.write("")

    console.print("[bold green]✓ JordanSec project initialized successfully.[/bold green]")


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL or domain (example.com)"),
    module: str = typer.Option("headers", "--module", "-m", help="Scan module"),
    timeout: int = typer.Option(10, "--timeout", "-t", help="Request timeout seconds"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save JSON report to file"),
):
    """
    Run security audit scan.
    """
    if module != "headers":
        console.print("[red]Unknown module. Available: headers[/red]")
        raise typer.Exit(1)

    console.print(f"[cyan]Running headers audit on {target}...[/cyan]")
    res = audit_headers(target, timeout=timeout)

    if res.error:
        console.print(f"[red]Error: {res.error}[/red]")
        raise typer.Exit(1)

    score, grade = score_headers(res)
    if res.https:
        console.print("[green]✓ HTTPS enabled[/green]")
    else:
        console.print("[yellow]! HTTPS not enabled[/yellow]")

    console.print(f"[bold]Score:[/bold] {score}/100   [bold]Grade:[/bold] {grade}")

    if res.missing:
        console.print("[yellow]Missing security headers:[/yellow]")
        for h in res.missing:
            console.print(f"  - {h}")
    else:
        console.print("[green]✓ All common security headers present[/green]")

    if res.warnings:
        console.print("[red]Warnings:[/red]")
        for w in res.warnings:
            console.print(f"  - {w}")

    if output:
        saved = save_json(res.to_dict(), output)
        console.print(f"[green]✓ Saved report to:[/green]\n{saved}")


if __name__ == "__main__":
    app()

