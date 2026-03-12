# core/output.py — ANSI color output, tables, banner

RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"


def info(msg: str) -> None:
    print(f"{BLUE}[*]{RESET} {msg}")


def success(msg: str) -> None:
    print(f"{GREEN}[+]{RESET} {msg}")


def warning(msg: str) -> None:
    print(f"{YELLOW}[!]{RESET} {msg}")


def error(msg: str) -> None:
    print(f"{RED}[-]{RESET} {msg}")


def banner() -> None:
    art = f"""{RED}{BOLD}
  ██████╗ ███████╗██████╗ ████████╗ ██████╗  ██████╗ ██╗
  ██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔═══██╗██╔═══██╗██║
  ██████╔╝█████╗  ██║  ██║   ██║   ██║   ██║██║   ██║██║
  ██╔══██╗██╔══╝  ██║  ██║   ██║   ██║   ██║██║   ██║██║
  ██║  ██║███████╗██████╔╝   ██║   ╚██████╔╝╚██████╔╝███████╗
  ╚═╝  ╚═╝╚══════╝╚═════╝    ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝{RESET}
{DIM}                 Red Team Framework — Lab Edition{RESET}
{CYAN}                        [ Type 'help' to start ]{RESET}
"""
    print(art)


def table(headers: list, rows: list) -> None:
    """Print a formatted table with headers and rows."""
    if not rows and not headers:
        return

    col_widths = [len(str(h)) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(col_widths):
                col_widths[i] = max(col_widths[i], len(str(cell)))

    sep = "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"
    header_row = "|" + "|".join(
        f" {BOLD}{str(h).ljust(col_widths[i])}{RESET} "
        for i, h in enumerate(headers)
    ) + "|"

    print(sep)
    print(header_row)
    print(sep)
    for row in rows:
        cells = list(row) + [""] * (len(headers) - len(row))
        line = "|" + "|".join(
            f" {str(cells[i]).ljust(col_widths[i])} "
            for i in range(len(headers))
        ) + "|"
        print(line)
    print(sep)
