# core/session.py — Target and session management

from datetime import datetime


class Target:
    _id_counter = 0

    def __init__(self, ip: str, hostname: str = "", os: str = "", notes: str = ""):
        Target._id_counter += 1
        self.id        = Target._id_counter
        self.ip        = ip
        self.hostname  = hostname
        self.os        = os
        self.notes     = notes
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def __repr__(self) -> str:
        return f"Target(id={self.id}, ip={self.ip})"


class SessionManager:
    def __init__(self):
        self._targets: dict[int, Target] = {}
        self._active_id: int | None = None

    # --- Targets ---

    def add_target(self, ip: str, hostname: str = "", os: str = "", notes: str = "") -> Target:
        t = Target(ip, hostname, os, notes)
        self._targets[t.id] = t
        return t

    def remove_target(self, target_id: int) -> bool:
        if target_id in self._targets:
            del self._targets[target_id]
            if self._active_id == target_id:
                self._active_id = None
            return True
        return False

    def list_targets(self) -> list:
        return list(self._targets.values())

    def get_target(self, target_id: int) -> Target | None:
        return self._targets.get(target_id)

    # --- Active target ---

    def set_active(self, target_id: int) -> bool:
        if target_id in self._targets:
            self._active_id = target_id
            return True
        return False

    def get_active(self) -> Target | None:
        if self._active_id is not None:
            return self._targets.get(self._active_id)
        return None

    def clear_active(self) -> None:
        self._active_id = None
