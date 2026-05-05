"""
RUBlocker84 Background DNS Service.

A standalone DNS server that blocks tracking domains without CLI.
"""

import signal
import sys
import threading
import time

from blocker.config import load_config, get_blocked_hosts, get_resource_path
from blocker.dns_server import DNSServer
from blocker.hosts import HOSTS_FILE, BLOCK_IP

import logging
import pythoncom
import wmi
import json
import os

LOCAL_IP = "127.0.1.10"
DNS_CACHE_FILE = get_resource_path("dns_backup.json")
LOG_FILE = get_resource_path("dnsblocker.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

stop_event = threading.Event()


def get_forwarders() -> list[str]:
    pythoncom.CoInitialize()
    try:
        adapters = {}
        c = wmi.WMI()
        for nic in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
            adapters[nic.Description] = list(nic.DNSServerSearchOrder or [])
        forwarders = []
        for dns_list in adapters.values():
            forwarders.extend(dns_list)
        return list(filter(lambda x: x != LOCAL_IP, forwarders))
    finally:
        pythoncom.CoUninitialize()


def _backup_current_dns() -> dict[str, list[str]]:
    """Backup current DNS settings for all adapters."""
    adapters = {}
    try:
        c = wmi.WMI()
        for nic in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
            if nic.Description:
                adapters[nic.Description] = list(nic.DNSServerSearchOrder or [])
    except Exception as e:
        logger.error(f"Failed to backup DNS settings: {e}")
    return adapters


def _set_dns_for_adapters(dns_list: list[str]) -> bool:
    """Set DNS servers for all network adapters to dns_list.
    Returns True if at least one adapter succeeded."""
    success = False
    try:
        c = wmi.WMI()
        for nic in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
            if nic.Description:
                try:
                    result = nic.SetDNSServerSearchOrder(dns_list)
                    if result[0] == 0:
                        logger.info(f"DNS for adapter {nic.Description} set to {dns_list}")
                        success = True
                    else:
                        logger.error(
                            f"Failed to set DNS for {nic.Description}, error code {result[0]}"
                        )
                except Exception as e:
                    logger.error(f"Exception setting DNS for {nic.Description}: {e}")
    except Exception as e:
        logger.error(f"WMI initialization failed: {e}")
    return success


def ensure_local_dns() -> None:
    """Ensure system DNS is set to LOCAL_IP; backup current settings first."""
    if os.path.exists(DNS_CACHE_FILE):
        logger.info("DNS backup already exists, skipping backup.")
    else:
        adapters = _backup_current_dns()
        if adapters:
            try:
                with open(DNS_CACHE_FILE, "w", encoding="utf-8") as f:
                    json.dump(adapters, f, indent=2)
                logger.info("DNS settings backed up.")
            except Exception as e:
                logger.error(f"Failed to write DNS backup: {e}")
        else:
            logger.warning("No adapters found; DNS backup skipped.")
    # Set DNS to local IP
    if _set_dns_for_adapters([LOCAL_IP]):
        logger.info(f"DNS set to {LOCAL_IP} for all adapters.")
    else:
        logger.error("Failed to set DNS to local IP.")


def restore_original_dns() -> None:
    """Restore DNS settings from backup file."""
    if not os.path.exists(DNS_CACHE_FILE):
        logger.warning("DNS backup file not found; nothing to restore.")
        return
    try:
        with open(DNS_CACHE_FILE, "r", encoding="utf-8") as f:
            adapters = json.load(f)
    except Exception as e:
        logger.error(f"Failed to read DNS backup: {e}")
        return
    if not adapters:
        logger.warning("DNS backup is empty; nothing to restore.")
        return
    # Restore each adapter
    try:
        c = wmi.WMI()
        for nic in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
            if nic.Description and nic.Description in adapters:
                dns_list = adapters[nic.Description]
                try:
                    result = nic.SetDNSServerSearchOrder(dns_list)
                    if result[0] == 0:
                        logger.info(
                            f"DNS for adapter {nic.Description} restored to {dns_list}"
                        )
                    else:
                        logger.error(
                            f"Failed to restore DNS for {nic.Description}, error {result[0]}"
                        )
                except Exception as e:
                    logger.error(
                        f"Exception restoring DNS for {nic.Description}: {e}"
                    )
    except Exception as e:
        logger.error(f"WMI initialization failed during restore: {e}")
    # Optionally remove backup file after restore
    try:
        os.remove(DNS_CACHE_FILE)
        logger.info("DNS backup file removed after restore.")
    except Exception as e:
        logger.error(f"Failed to remove DNS backup file: {e}")


def run_dns() -> None:
    config = load_config()
    forwarders = get_forwarders()
    dns = DNSServer(get_blocked_hosts(config), forwarders)

    def run():
        try:
            dns.start()
        except Exception as e:
            logger.error(f"DNS server error: {e}")

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    logger.info("Background DNS service started")


def signal_handler(sig, frame):
    stop_event.set()
    restore_original_dns()
    logger.info("Service stopped via signal")
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Ensure DNS points to our local server before starting
    ensure_local_dns()

    run_dns()

    try:
        while not stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        restore_original_dns()