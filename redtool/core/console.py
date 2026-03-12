# core/console.py — Interactive shell

import os
import sys
import readline
from pathlib import Path

from core.output import (
    info, success, warning, error, table,
    BOLD, RESET, CYAN, YELLOW, GREEN, RED, DIM
)
from core.session import SessionManager
from core.module_loader import ModuleLoader, BaseModule


HISTORY_FILE = Path.home() / ".redtool_history"


class Console:
    def __init__(self, modules_dir: Path):
        self.session       = SessionManager()
        self.loader        = ModuleLoader(modules_dir)
        self.active_module: BaseModule | None = None
        self._running      = True
        self._setup_readline()

    # ------------------------------------------------------------------ #
    #  readline                                                            #
    # ------------------------------------------------------------------ #

    def _setup_readline(self) -> None:
        readline.set_completer(self._completer)
        readline.parse_and_bind("tab: complete")
        readline.set_completer_delims(" \t")
        if HISTORY_FILE.exists():
            readline.read_history_file(str(HISTORY_FILE))

    def _completer(self, text: str, state: int) -> str | None:
        buffer = readline.get_line_buffer().lstrip()
        tokens = buffer.split()

        top_commands = [
            "help", "?", "use", "back", "show", "set", "run", "exploit",
            "sessions", "target", "info", "clear", "exit", "quit",
        ]

        completions: list[str] = []

        if not tokens or (len(tokens) == 1 and not buffer.endswith(" ")):
            completions = [c for c in top_commands if c.startswith(text)]
        elif tokens[0] == "use":
            mods = [m["path"] for m in self.loader.list_modules()]
            completions = [m for m in mods if m.startswith(text)]
        elif tokens[0] == "show":
            completions = [s for s in ["modules", "options"] if s.startswith(text)]
        elif tokens[0] == "target":
            completions = [s for s in ["add", "del", "set"] if s.startswith(text)]
        elif tokens[0] == "set" and self.active_module:
            opts = list(self.active_module.options.keys())
            completions = [o for o in opts if o.upper().startswith(text.upper())]

        return completions[state] if state < len(completions) else None

    def _save_history(self) -> None:
        try:
            readline.write_history_file(str(HISTORY_FILE))
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    #  Prompt                                                              #
    # ------------------------------------------------------------------ #

    @property
    def _prompt(self) -> str:
        if self.active_module:
            cat  = self.active_module.category
            name = self.active_module.name
            return (
                f"{BOLD}{RED}redtool{RESET}"
                f"{DIM}({RESET}{YELLOW}{cat}/{name}{RESET}{DIM}){RESET}"
                f"{BOLD}{RED}> {RESET}"
            )
        return f"{BOLD}{RED}redtool{RESET}{BOLD}{RED}> {RESET}"

    # ------------------------------------------------------------------ #
    #  Main loop                                                           #
    # ------------------------------------------------------------------ #

    def run(self) -> None:
        while self._running:
            try:
                line = input(self._prompt).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                warning("Use 'exit' to quit.")
                continue

            if not line:
                continue

            self._dispatch(line)

        self._save_history()

    def _dispatch(self, line: str) -> None:
        parts = line.split()
        cmd   = parts[0].lower()
        args  = parts[1:]

        dispatch = {
            "help":     self._cmd_help,
            "?":        self._cmd_help,
            "use":      self._cmd_use,
            "back":     self._cmd_back,
            "show":     self._cmd_show,
            "set":      self._cmd_set,
            "run":      self._cmd_run,
            "exploit":  self._cmd_run,
            "sessions": self._cmd_sessions,
            "target":   self._cmd_target,
            "info":     self._cmd_info,
            "clear":    self._cmd_clear,
            "exit":     self._cmd_exit,
            "quit":     self._cmd_exit,
        }

        handler = dispatch.get(cmd)
        if handler:
            handler(args)
        else:
            error(f"Unknown command: '{cmd}'. Type 'help' for usage.")

    # ------------------------------------------------------------------ #
    #  Command handlers                                                    #
    # ------------------------------------------------------------------ #

    def _cmd_help(self, args: list) -> None:
        cmds = [
            ("help / ?",              "Show this help message"),
            ("use <module>",          "Load a module (e.g. use recon/portscan)"),
            ("back",                  "Unload the active module"),
            ("show modules",          "List all available modules"),
            ("show options",          "Show options for the active module"),
            ("set <KEY> <value>",     "Set a module option"),
            ("run / exploit",         "Execute the active module"),
            ("info",                  "Show info about the active module"),
            ("sessions",              "List all targets/sessions"),
            ("target add <ip>",       "Add a target"),
            ("target del <id>",       "Remove a target by ID"),
            ("target set <id>",       "Set active target by ID"),
            ("clear",                 "Clear the screen"),
            ("exit / quit",           "Exit redtool"),
        ]
        print(f"\n{BOLD}Available commands:{RESET}")
        table(["Command", "Description"], cmds)
        print()

    def _cmd_use(self, args: list) -> None:
        if not args:
            error("Usage: use <module/path>")
            return
        path = args[0]
        mod  = self.loader.load(path)
        if mod is None:
            error(f"Module not found: '{path}'")
            hint = self._fuzzy_hint(path)
            if hint:
                info(f"Did you mean: {CYAN}{hint}{RESET}?")
            return
        self.active_module = mod
        success(f"Loaded module: {CYAN}{path}{RESET}")
        if mod.options:
            info("Run 'show options' to see configurable options.")

    def _cmd_back(self, args: list) -> None:
        if self.active_module:
            info(f"Unloaded module: {self.active_module.name}")
            self.active_module = None
        else:
            warning("No active module.")

    def _cmd_show(self, args: list) -> None:
        if not args:
            error("Usage: show <modules|options>")
            return

        sub = args[0].lower()

        if sub == "modules":
            mods = self.loader.list_modules()
            if not mods:
                warning("No modules found.")
                return
            rows = [(m["path"], m["category"], m["description"]) for m in mods]
            print(f"\n{BOLD}Loaded modules:{RESET}")
            table(["Path", "Category", "Description"], rows)
            print()

        elif sub == "options":
            if not self.active_module:
                warning("No active module. Use 'use <module>' first.")
                return
            opts = self.active_module.options
            if not opts:
                info("This module has no configurable options.")
                return
            rows = [
                (
                    k,
                    str(v.get("value", "")),
                    "yes" if v.get("required") else "no",
                    v.get("description", ""),
                )
                for k, v in opts.items()
            ]
            print(f"\n{BOLD}Options for {self.active_module.name}:{RESET}")
            table(["Option", "Value", "Required", "Description"], rows)
            print()

        else:
            error(f"Unknown show sub-command: '{sub}'")

    def _cmd_set(self, args: list) -> None:
        if not self.active_module:
            warning("No active module.")
            return
        if len(args) < 2:
            error("Usage: set <KEY> <value>")
            return
        key   = args[0]
        value = " ".join(args[1:])
        self.active_module.set_option(key, value)
        success(f"{key.upper()} => {value}")

    def _cmd_run(self, args: list) -> None:
        if not self.active_module:
            warning("No active module. Use 'use <module>' first.")
            return
        missing = self.active_module.validate()
        if missing:
            error(f"Missing required options: {', '.join(missing)}")
            return
        try:
            self.active_module.run()
        except KeyboardInterrupt:
            warning("Module execution interrupted.")
        except Exception as exc:
            error(f"Module error: {exc}")

    def _cmd_sessions(self, args: list) -> None:
        targets = self.session.list_targets()
        if not targets:
            info("No targets registered. Use 'target add <ip>'.")
            return
        active = self.session.get_active()
        rows = []
        for t in targets:
            marker = f"{GREEN}*{RESET}" if (active and t.id == active.id) else " "
            rows.append((
                f"{marker}{t.id}",
                t.ip,
                t.hostname or "-",
                t.os or "-",
                t.timestamp,
                t.notes or "-",
            ))
        print(f"\n{BOLD}Targets:{RESET}")
        table(["ID", "IP", "Hostname", "OS", "Added", "Notes"], rows)
        print()

    def _cmd_target(self, args: list) -> None:
        if not args:
            error("Usage: target <add|del|set> [args]")
            return
        sub = args[0].lower()

        if sub == "add":
            if len(args) < 2:
                error("Usage: target add <ip> [hostname] [os]")
                return
            ip       = args[1]
            hostname = args[2] if len(args) > 2 else ""
            os_name  = args[3] if len(args) > 3 else ""
            t = self.session.add_target(ip, hostname, os_name)
            success(f"Target added: [{t.id}] {t.ip}")

        elif sub == "del":
            if len(args) < 2:
                error("Usage: target del <id>")
                return
            try:
                tid = int(args[1])
            except ValueError:
                error("ID must be an integer.")
                return
            if self.session.remove_target(tid):
                success(f"Target {tid} removed.")
            else:
                error(f"Target {tid} not found.")

        elif sub == "set":
            if len(args) < 2:
                error("Usage: target set <id>")
                return
            try:
                tid = int(args[1])
            except ValueError:
                error("ID must be an integer.")
                return
            if self.session.set_active(tid):
                t = self.session.get_active()
                success(f"Active target: [{t.id}] {t.ip}")
            else:
                error(f"Target {tid} not found.")

        else:
            error(f"Unknown target sub-command: '{sub}'")

    def _cmd_info(self, args: list) -> None:
        if not self.active_module:
            warning("No active module.")
            return
        m = self.active_module
        print(f"""
{BOLD}Module information:{RESET}
  {BOLD}Name:{RESET}        {m.name}
  {BOLD}Category:{RESET}    {m.category}
  {BOLD}Description:{RESET} {m.description}
  {BOLD}Author:{RESET}      {m.author}
""")

    def _cmd_clear(self, args: list) -> None:
        os.system("clear")

    def _cmd_exit(self, args: list) -> None:
        info("Goodbye.")
        self._running = False

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    def _fuzzy_hint(self, path: str) -> str | None:
        """Return the closest module path if any substring matches."""
        mods = [m["path"] for m in self.loader.list_modules()]
        needle = path.lower()
        for m in mods:
            if needle in m.lower() or m.lower() in needle:
                return m
        # Try matching last component
        last = path.split("/")[-1]
        for m in mods:
            if last in m:
                return m
        return None
