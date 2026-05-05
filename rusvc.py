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

LOCAL_IP = "127.0.1.10"
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


def backup_dns() -> dict:
    import json
    DNS_CACHE_FILE = get_resource_path("dns_backup.json")
    adapters = get_forwarders()
    with open(DNS_CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(adapters, f, indent=2)
    return adapters


def restore_dns() -> None:
    import json
    DNS_CACHE_FILE = get_resource_path("dns_backup.json")
    if not DNS_CACHE_FILE:
        return
    try:
        with open(DNS_CACHE_FILE, "r", encoding="utf-8") as f:
            adapters = json.load(f)
        for adapter, dns_list in adapters.items():
            try:
                c = wmi.WMI()
                for nic in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
                    if nic.Description == adapter:
                        nic.SetDNSServerSearchOrder(dns_list)
            except Exception:
                pass
    except Exception:
        pass


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
    restore_dns()
    logger.info("Service stopped")
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    run_dns()

    try:
        while not stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        restore_dns()