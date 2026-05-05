"""
RUBlocker84 - Local DNS-based tracker blocker.

This module provides the entry point for running RUBlocker84 as a
Windows service or standalone DNS server.
"""

import ctypes
import logging
import os
import sys
import threading
import time
import traceback
from typing import Optional

import pythoncom
import wmi

from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A

from blocker.config import (
    Config, load_config, save_config, get_blocked_hosts, get_resource_path
)
from blocker.dns_server import DNSServer
from blocker.hosts import HostsManager

# Constants
LOCAL_IP = "127.0.1.10"
DNS_PORT = 53
LOG_FILE = get_resource_path("dnsblocker.log")
DNS_CACHE_FILE = get_resource_path("dns_backup.json")

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def get_adapters_dns() -> dict[str, list[str]]:
    pythoncom.CoInitialize()
    try:
        adapters = {}
        c = wmi.WMI()
        for nic in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
            adapters[nic.Description] = list(nic.DNSServerSearchOrder or [])
            logger.info(f"Adapter found: {nic.Description} DNS: {nic.DNSServerSearchOrder}")
        return adapters
    finally:
        pythoncom.CoUninitialize()


def set_adapter_dns(adapter: str, dns_list: list[str]) -> bool:
    pythoncom.CoInitialize()
    try:
        c = wmi.WMI()
        for nic in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
            if nic.Description == adapter:
                res = nic.SetDNSServerSearchOrder(dns_list)
                if res[0] == 0:
                    logger.info(f"DNS for adapter {adapter} set: {dns_list}")
                else:
                    logger.error(f"Error setting DNS for {adapter}, code {res[0]}")
                return True
    except Exception as e:
        logger.error(f"Exception setting DNS for {adapter}: {e}")
    finally:
        pythoncom.CoUninitialize()
    return False


def backup_and_set_local_dns() -> dict[str, list[str]]:
    adapters = get_adapters_dns()
    logger.info(f"Total adapters: {len(adapters)}")

    already_local = any(
        LOCAL_IP in dns_list for dns_list in adapters.values()
    )
    if not already_local:
        import json
        with open(DNS_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(adapters, f, indent=2)
        logger.info("DNS backup saved.")
    else:
        logger.info("Local DNS already set, backup not overwritten.")

    for adapter, dns_list in adapters.items():
        try:
            if LOCAL_IP not in dns_list:
                new_dns = [LOCAL_IP] + dns_list
                set_adapter_dns(adapter, new_dns)
                logger.info(f"DNS for adapter {adapter} changed to {new_dns}")
            else:
                logger.info(f"DNS for adapter {adapter} already contains {LOCAL_IP}")
        except Exception as e:
            logger.error(f"Error setting DNS for {adapter}: {e}")

    return adapters


def restore_dns() -> None:
    import json
    if not os.path.exists(DNS_CACHE_FILE):
        return
    try:
        with open(DNS_CACHE_FILE, "r", encoding="utf-8") as f:
            adapters = json.load(f)
        for adapter, dns_list in adapters.items():
            try:
                if dns_list:
                    set_adapter_dns(adapter, dns_list)
                    logger.info(f"DNS for adapter {adapter} restored to {dns_list}")
            except Exception as e:
                logger.error(f"Error restoring DNS for {adapter}: {e}")
    except Exception as e:
        logger.error(f"Error reading DNS cache: {e}")


# Try to import pywin32 for service support
try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager

    HAS_PYWIN32 = True
except ImportError:
    HAS_PYWIN32 = False


class RUBlockerService(win32serviceutil.ServiceFramework) if HAS_PYWIN32 else object:
    _svc_name_ = "RUB84Service"
    _svc_display_name_ = "RUBlocker84 DNS Blocker"
    _svc_description_ = "Block domains via local DNS server"

    def __init__(self, args):
        if HAS_PYWIN32:
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.stop_event = threading.Event()
        self.dns_server: Optional[DNSServer] = None

    def SvcStop(self):
        if HAS_PYWIN32:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        restore_dns()
        self.stop_event.set()
        if HAS_PYWIN32:
            win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        if not HAS_PYWIN32:
            return
        try:
            self.ReportServiceStatus(win32service.SERVICE_START_PENDING)
            logger.info("Service starting...")

            config = load_config()
            forwarders = self._get_forwarders()

            self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            logger.info("Service running with active presets.")

            self.dns_server = DNSServer(get_blocked_hosts(config), forwarders)
            threading.Thread(target=self.dns_server.start, daemon=True).start()

            win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)

        except Exception:
            logger.exception("Service error")

    def _get_forwarders(self) -> list[str]:
        adapters = get_adapters_dns()
        forwarders = []
        for dns_list in adapters.values():
            forwarders.extend(dns_list)
        return list(filter(lambda x: x != LOCAL_IP, forwarders))


def install_service() -> None:
    if not HAS_PYWIN32:
        print("PyWin32 not installed")
        return

    svc_name = RUBlockerService._svc_name_
    try:
        status = win32serviceutil.QueryServiceStatus(svc_name)
        if status:
            print(f"Service '{svc_name}' already exists. Removing...")
            import subprocess
            subprocess.run(["sc", "stop", svc_name], shell=True,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(2)
            subprocess.run(["sc", "delete", svc_name], shell=True,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logger.info("Service removed.")
            for _ in range(10):
                try:
                    win32serviceutil.QueryServiceStatus(svc_name)
                    time.sleep(2)
                except Exception:
                    break
            return
    except Exception:
        pass

    win32serviceutil.InstallService(
        None, svc_name, RUBlockerService._svc_display_name_,
        description=RUBlockerService._svc_description_,
        startType=win32service.SERVICE_AUTO_START,
        exeArgs="run"
    )
    logger.info(f"Service '{svc_name}' installed.")


def run_dns_server(config: Config) -> None:
    adapters = backup_and_set_local_dns()
    forwarders = []
    for dns_list in adapters.values():
        forwarders.extend(dns_list)
    forwarders = list(filter(lambda x: x != LOCAL_IP, forwarders))

    dns = DNSServer(get_blocked_hosts(config), forwarders)
    try:
        dns.start()
    except KeyboardInterrupt:
        dns.stop()
        restore_dns()
        logger.info("DNS server stopped.")


def _apply_initial_hosts_state(config: Config) -> None:
    from blocker.hosts import HostsManager
    hosts_manager = HostsManager()
    for group_name, group in config.groups.items():
        hosts_manager.update_group(group.hosts, enable=group.on)


def main() -> None:
    if HAS_PYWIN32 and len(sys.argv) > 1:
        cmd = sys.argv[1].lower()

        if cmd == "cli":
            pass  # CLI mode - handled by rucli.py
        elif cmd == "install-service":
            install_service()
            import subprocess
            subprocess.run(["sc", "config", RUBlockerService._svc_name_, "start=", "auto"], shell=True)
            subprocess.run(["net", "start", RUBlockerService._svc_name_], shell=True)
        elif cmd == "remove-service":
            import subprocess
            subprocess.run(["sc", "stop", RUBlockerService._svc_name_], shell=True)
            subprocess.run(["sc", "delete", RUBlockerService._svc_name_], shell=True)
        else:
            win32serviceutil.HandleCommandLine(RUBlockerService)
    else:
        config = load_config()
        _apply_initial_hosts_state(config)
        run_dns_server(config)


if __name__ == "__main__":
    main()