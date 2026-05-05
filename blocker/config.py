"""Configuration management for RUBlocker84."""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
import threading
import time


@dataclass
class BlockGroup:
    on: bool = False
    description: str = ""
    hosts: list[str] = field(default_factory=list)
    kernel: bool = False


@dataclass
class Config:
    active_groups: list[str] = field(default_factory=list)
    groups: dict[str, BlockGroup] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Config":
        groups = {}
        for name, group_data in data.get("groups", {}).items():
            groups[name] = BlockGroup(
                on=group_data.get("on", False),
                description=group_data.get("description", ""),
                hosts=group_data.get("hosts", []),
                kernel=group_data.get("kernel", False),
            )
        return cls(
            active_groups=data.get("active_groups", []),
            groups=groups,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "active_groups": self.active_groups,
            "groups": {
                name: {
                    "on": group.on,
                    "description": group.description,
                    "hosts": group.hosts,
                    "kernel": group.kernel,
                }
                for name, group in self.groups.items()
            },
        }


def get_resource_path(filename: str) -> str:
    if getattr(__import__("sys"), "frozen", False):
        base_path = os.path.dirname(__import__("sys").executable)
    else:
        base_path = os.path.dirname(__file__)
    return os.path.join(base_path, filename)


CONFIG_FILE = get_resource_path("config.json")


def load_config() -> Config:
    if not os.path.exists(CONFIG_FILE):
        return Config()
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return Config.from_dict(data)
    except (json.JSONDecodeError, KeyError):
        return Config()


def save_config(config: Config) -> None:
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config.to_dict(), f, indent=2)


def get_blocked_hosts(config: Config) -> list[str]:
    blocked = []
    for group in config.groups.values():
        if group.on:
            blocked.extend(group.hosts)
    return list(set(blocked))


class ConfigWatcher:
    """Watch configuration file for changes and reload when modified."""

    def __init__(self, config_file: str, callback: callable):
        self.config_file = Path(config_file)
        self.callback = callback
        self._last_mtime: Optional[float] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def _check(self) -> None:
        try:
            mtime = self.config_file.stat().st_mtime
            if self._last_mtime is None:
                self._last_mtime = mtime
                return

            if mtime > self._last_mtime:
                self._last_mtime = mtime
                new_config = load_config()
                self.callback(new_config)
        except Exception:
            pass

    def start(self, interval: float = 1.0) -> None:
        self._running = True
        self._thread = threading.Thread(
            target=self._watch_loop,
            args=(interval,),
            daemon=True
        )
        self._thread.start()

    def _watch_loop(self, interval: float) -> None:
        while self._running:
            self._check()
            time.sleep(interval)

    def stop(self) -> None:
        self._running = False