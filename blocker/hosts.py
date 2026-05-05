"""Hosts file management for RUBlocker84."""

import logging
import os
import re
from typing import Optional

logger = logging.getLogger(__name__)

HOSTS_FILE = (
    r"C:\Windows\System32\drivers\etc\hosts"
    if os.name == "nt"
    else "/etc/hosts"
)
BLOCK_IP = "127.0.0.2"

# Valid hostname pattern (RFC 1123)
HOSTNAME_PATTERN = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$")


def validate_host(host: str) -> bool:
    """Validate a hostname or domain."""
    if not host or len(host) > 253:
        return False
    return bool(HOSTNAME_PATTERN.match(host))


def sanitize_hosts(hosts: list[str]) -> list[str]:
    """Filter out invalid hosts."""
    return [h for h in hosts if validate_host(h)]


class HostsManager:
    def __init__(self, hosts_file: str = HOSTS_FILE):
        self.hosts_file = hosts_file

    def update_group(self, hosts: list[str], enable: bool) -> bool:
        hosts = sanitize_hosts(hosts)
        if not hosts:
            return True

        try:
            with open(self.hosts_file, "r", encoding="utf-8") as f:
                content = f.read()
                lines = content.splitlines(keepends=True)
        except PermissionError:
            logger.error("Permission denied: run as Administrator")
            return False
        except FileNotFoundError:
            logger.error(f"Hosts file not found: {self.hosts_file}")
            return False
        except Exception as e:
            logger.error(f"Cannot read hosts file: {e}")
            return False

        new_lines = []
        changed = False

        for line in lines:
            stripped = line.strip()
            if not stripped:
                new_lines.append(line)
                continue

            if enable:
                new_lines.append(line)
            else:
                if any(
                    stripped.endswith(host) and stripped.startswith(BLOCK_IP)
                    for host in hosts
                ):
                    logger.info(f"Removing hosts entry: {stripped}")
                    changed = True
                    continue
                new_lines.append(line)

        if enable:
            for host in hosts:
                entry = f"{BLOCK_IP} {host}\n"
                if entry not in lines:
                    new_lines.append(entry)
                    logger.info(f"Adding hosts entry: {entry.strip()}")
                    changed = True

        if changed:
            try:
                with open(self.hosts_file, "w", encoding="utf-8") as f:
                    f.writelines(new_lines)
                logger.info("Hosts file updated")
            except PermissionError:
                logger.error("Permission denied: run as Administrator")
                return False
            except Exception as e:
                logger.error(f"Cannot write hosts file: {e}")
                return False

        return True