# core/module_loader.py — Dynamic module loading

import importlib.util
import inspect
import sys
from pathlib import Path
from abc import ABC, abstractmethod


class BaseModule(ABC):
    name:        str = "base"
    description: str = "Base module"
    author:      str = "unknown"
    category:    str = "misc"

    def __init__(self):
        self.options: dict = {}

    def set_option(self, key: str, value: str) -> None:
        key = key.upper()
        if key in self.options:
            self.options[key]["value"] = value
        else:
            self.options[key] = {"value": value, "required": False, "description": ""}

    def get_option(self, key: str):
        key = key.upper()
        entry = self.options.get(key)
        return entry["value"] if entry else None

    def validate(self) -> list:
        """Return list of missing required option names."""
        missing = []
        for k, v in self.options.items():
            if v.get("required") and not v.get("value"):
                missing.append(k)
        return missing

    @abstractmethod
    def run(self) -> None:
        pass


class ModuleLoader:
    def __init__(self, modules_dir: Path):
        self.modules_dir = modules_dir
        self._registry: dict[str, dict] = {}  # path → {name, description, category, file}
        self._scan()

    def _scan(self) -> None:
        """Scan modules_dir recursively for BaseModule subclasses."""
        self._registry.clear()
        if not self.modules_dir.exists():
            return

        for py_file in self.modules_dir.rglob("*.py"):
            if py_file.name.startswith("_"):
                continue
            self._inspect_file(py_file)

    def _inspect_file(self, py_file: Path) -> None:
        try:
            spec = importlib.util.spec_from_file_location(
                f"_rt_mod_{py_file.stem}", py_file
            )
            if spec is None or spec.loader is None:
                return
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore[attr-defined]

            for _, cls in inspect.getmembers(mod, inspect.isclass):
                if (
                    issubclass(cls, BaseModule)
                    and cls is not BaseModule
                    and not inspect.isabstract(cls)
                ):
                    rel = py_file.relative_to(self.modules_dir)
                    parts = list(rel.parts)
                    parts[-1] = parts[-1].replace(".py", "")
                    module_path = "/".join(parts)

                    instance = cls()
                    self._registry[module_path] = {
                        "name":        instance.name,
                        "description": instance.description,
                        "category":    instance.category,
                        "author":      instance.author,
                        "file":        str(py_file),
                        "class":       cls,
                    }
        except Exception:
            pass  # Skip files that fail to import

    def list_modules(self) -> list:
        """Return list of dicts with module metadata."""
        return [
            {
                "path":        path,
                "name":        info["name"],
                "description": info["description"],
                "category":    info["category"],
                "author":      info["author"],
            }
            for path, info in sorted(self._registry.items())
        ]

    def load(self, module_path: str) -> BaseModule | None:
        """Instantiate a module by its path (e.g. 'recon/portscan')."""
        info = self._registry.get(module_path)
        if info is None:
            return None
        return info["class"]()

    def refresh(self) -> None:
        self._scan()
