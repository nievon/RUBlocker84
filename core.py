"""
RUBlocker84 CLI + Windows Service
Block domains via local DNS server using config presets.
"""

import os
import sys
import socket
import threading
import json
import time
import ctypes
import subprocess
import wmi
import select
import time
import pythoncom
import traceback

from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A

# pywin32 for service
try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager

    HAS_PYWIN32 = True
except ImportError:
    HAS_PYWIN32 = False


def resource_path(filename):
    if getattr(sys, "frozen", False):  # exe
        base_path = os.path.dirname(sys.executable)
    else:  # py
        base_path = os.path.dirname(__file__)
    return os.path.join(base_path, filename)


CONFIG_FILE = resource_path("config.json")
LOG_FILE = resource_path("dnsblocker.log")
DNS_CACHE_FILE = resource_path("dns_backup.json")
HOSTS_FILE = (
    r"C:\Windows\System32\drivers\etc\hosts" if os.name == "nt" else "/etc/hosts"
)
LOCAL_IP = "127.0.1.10"
DNS_PORT = 53


# ======== Logging ========
def log(msg: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    print(f"[{ts}] {msg}")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{ts}] {msg}\n")


# ======== Admin check ========
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


# if not is_admin():
#     print("Run the script as Administrator!")
#     sys.exit(1)


# ======== Config ========
def load_config():
    if not os.path.exists(CONFIG_FILE):
        log("Config file not found!")
        return {}
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_config(cfg):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


config = load_config()


def get_blocked_hosts(cfg):
    blocked = []
    for group_name, group in cfg.get("groups", {}).items():
        if group.get("on"):
            blocked.extend(group.get("hosts", []))
    return list(set(blocked))


blocked_hosts = get_blocked_hosts(config)


# ======== Network adapters ========
def get_adapters_dns():
    pythoncom.CoInitialize()
    try:
        adapters = {}
        c = wmi.WMI()
        for nic in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
            adapters[nic.Description] = nic.DNSServerSearchOrder or []
            log(f"Adapter found: {nic.Description} DNS: {nic.DNSServerSearchOrder}")
        return adapters
    finally:
        pythoncom.CoUninitialize()


def set_adapter_dns(adapter, dns_list):
    pythoncom.CoInitialize()
    try:
        c = wmi.WMI()
        for nic in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
            if nic.Description == adapter:
                try:
                    res = nic.SetDNSServerSearchOrder(dns_list)
                    if res[0] == 0:
                        log(f"DNS for adapter {adapter} set: {dns_list}")
                    else:
                        log(f"Error setting DNS for {adapter}, code {res[0]}")
                except Exception as e:
                    log(f"Exception setting DNS for {adapter}: {e}")
    finally:
        pythoncom.CoUninitialize()


def backup_and_set_local_dns():
    adapters = get_adapters_dns()
    log(f"Total adapters: {len(adapters)}")

    # Проверяем, есть ли уже LOCAL_IP в любом адаптере
    already_local = any(
        LOCAL_IP in (list(dns_list) if isinstance(dns_list, tuple) else dns_list)
        for dns_list in adapters.values()
    )
    if not already_local:
        with open(DNS_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(adapters, f, indent=2)
        log("DNS backup saved.")
    else:
        log("Local DNS already set, backup not overwritten.")

    for adapter, dns_list in adapters.items():
        # Приводим к списку
        dns_list = list(dns_list) if isinstance(dns_list, tuple) else dns_list
        try:
            if LOCAL_IP not in dns_list:
                new_dns = [LOCAL_IP] + dns_list
                set_adapter_dns(adapter, new_dns)
                log(f"DNS for adapter {adapter} changed to {new_dns}")
            else:
                log(f"DNS for adapter {adapter} already contains {LOCAL_IP}")
        except Exception as e:
            log(f"Error setting DNS for {adapter}: {e}")

    return adapters


def restore_dns():
    if not os.path.exists(DNS_CACHE_FILE):
        return
    with open(DNS_CACHE_FILE, "r", encoding="utf-8") as f:
        adapters = json.load(f)
    for adapter, dns_list in adapters.items():
        try:
            if dns_list:
                set_adapter_dns(adapter, dns_list)
                log(f"DNS for adapter {adapter} restored to {dns_list}")
        except Exception as e:
            log(f"Error restoring DNS for {adapter}: {e}")


# ======== DNS server ========
def handle_client(data, addr, sock, forwarders):
    try:
        request = DNSRecord.parse(data)
        qname = str(request.q.qname).rstrip(".")
        qtype = QTYPE[request.q.qtype]

        if any(qname.endswith(h) for h in blocked_hosts):
            reply = DNSRecord(
                DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q
            )
            reply.add_answer(RR(qname, QTYPE.A, rdata=A("0.0.0.0"), ttl=0))
            sock.sendto(reply.pack(), addr)
            log(f"BLOCKED {qname} ({addr[0]}:{addr[1]})")
        else:
            for forward in forwarders:
                try:
                    forward_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    forward_sock.settimeout(2)
                    forward_sock.sendto(data, (forward, DNS_PORT))
                    resp, _ = forward_sock.recvfrom(512)
                    sock.sendto(resp, addr)
                    # log(f"ALLOWED {qname} via {forward}")
                    break
                except Exception:
                    continue
    except Exception as e:
        log(f"Error handling {addr}: {e}")


def dns_server(forwarders, stop_event):
    pythoncom.CoInitialize()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((LOCAL_IP, DNS_PORT))
        log(f"DNS server running on {LOCAL_IP}:{DNS_PORT}")
        sock.setblocking(False)

        while not stop_event.is_set():
            ready = select.select([sock], [], [], 1.0)
            if ready[0]:
                try:
                    data, addr = sock.recvfrom(512)
                    threading.Thread(
                        target=handle_client,
                        args=(data, addr, sock, forwarders),
                        daemon=True,
                    ).start()
                except Exception as e:
                    log(f"Server error: {e}")
    finally:
        pythoncom.CoUninitialize()


# ======== CLI for presets ========
def clear_console():
    os.system("cls" if os.name == "nt" else "clear")


def update_kernel_hosts(group_name, enable=True):
    group = config["groups"].get(group_name)
    if not group or not group.get("kernel"):
        return

    urls = group.get("hosts", [])

    try:
        with open(HOSTS_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception as e:
        log(f"Cannot read hosts file: {e}")
        return

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
                stripped.endswith(url) and stripped.startswith("127.0.0.2")
                for url in urls
            ):
                log(f"Removing kernel host entry: {stripped}")
                changed = True
                continue
            else:
                new_lines.append(line)

    if enable:

        for url in urls:
            entry = f"127.0.0.2 {url}\n"
            if entry not in lines:
                new_lines.append(entry)
                log(f"Adding kernel host entry: {entry.strip()}")
                changed = True

    if changed:
        try:
            with open(HOSTS_FILE, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
            log(f"Hosts file updated for group '{group_name}'")
        except Exception as e:
            log(f"Cannot write to hosts file: {e}")
