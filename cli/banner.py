"""启动 Banner"""

from rich.console import Console

__version__ = "0.1.0"

_BANNER = r"""
[bold #00d4aa]  ██╗      [/][bold #1fa8bf]██████╗  [/][bold #3d7cd5]██████╗[/][bold #5c50ea]██╗   ██╗[/][bold #7b61ff]███████╗[/]
[bold #00d4aa]  ██║     [/][bold #1fa8bf]██╔═══██╗[/][bold #3d7cd5]██╔════╝[/][bold #5c50ea]██║   ██║[/][bold #7b61ff]██╔════╝[/]
[bold #00d4aa]  ██║     [/][bold #1fa8bf]██║   ██║[/][bold #3d7cd5]██║     [/][bold #5c50ea]██║   ██║[/][bold #7b61ff]███████╗[/]
[bold #00d4aa]  ██║     [/][bold #1fa8bf]██║   ██║[/][bold #3d7cd5]██║     [/][bold #5c50ea]██║   ██║[/][bold #7b61ff]╚════██║[/]
[bold #00d4aa]  ███████╗[/][bold #1fa8bf]╚██████╔╝[/][bold #3d7cd5]╚██████╗[/][bold #5c50ea]╚██████╔╝[/][bold #7b61ff]███████║[/]
[bold #00d4aa]  ╚══════╝ [/][bold #1fa8bf]╚═════╝  [/][bold #3d7cd5]╚═════╝ [/][bold #5c50ea]╚═════╝ [/][bold #7b61ff]╚══════╝[/]
"""


def print_banner():
    console = Console()
    console.print(_BANNER)
    console.print(
        f"  [dim]Autonomous Agentic Pentest Framework[/]  "
        f"[bold yellow]v{__version__}[/]\n"
    )
