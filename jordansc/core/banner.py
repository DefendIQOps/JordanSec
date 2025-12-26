from rich.align import Align
from rich.panel import Panel
from rich.text import Text


def big_logo() -> str:
    # ASCII (خفيف ومناسب للجوال)
    return r"""
     __            __              _____          
    / /___  ____  / /___ _____    / ___/___  _____
   / / __ \/ __ \/ / __ `/ __ \   \__ \/ _ \/ ___/
  / / /_/ / /_/ / / /_/ / / / /  ___/ /  __/ /    
 /_/\____/\____/_/\__,_/_/ /_/  /____/\___/_/     
"""


def about_panel(app_name: str, author: str, lang: str = "en") -> Panel:
    if lang.lower() == "ar":
        title = f"{app_name}"
        lines = [
            f"{app_name}",
            "Professional, fast security auditing tool",
            "Cybersecurity & Security Auditing",
            "",
            f"Developed by: {author} 🇯🇴",
            "Try: python cli.py --help",
        ]
    else:
        title = f"{app_name}"
        lines = [
            f"{app_name}",
            "Professional, fast security auditing tool",
            "Cybersecurity & Security Auditing",
            "",
            f"Developed by: {author} 🇯🇴",
            "Try: python cli.py --help",
        ]

    text = Text("\n".join(lines))
    return Panel(
        Align.left(text),
        title=title,
        border_style="green",
        padding=(1, 2),
    )
