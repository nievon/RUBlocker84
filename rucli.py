"""
RUBlocker84 CLI Application.

Provides interactive command-line interface for managing the tracker blocker.
"""

import os
import socket
import subprocess
import sys
import threading
import time
import ctypes

import logging


# Ensure the script is running with administrator privileges
def run_as_admin() -> None:
    """Re-launch the script with administrator privileges if not already running as admin."""
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        is_admin = False
    if not is_admin:
        # Request elevation
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit(0)


# Run the admin check at startup
run_as_admin()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

# Import from blocker package
from blocker.config import (
    Config, load_config, save_config, get_blocked_hosts, get_resource_path
)
from blocker.dns_server import DNSServer
from blocker.hosts import HostsManager, HOSTS_FILE, BLOCK_IP

LOCAL_IP = "127.0.1.10"

# Global state
config: Config = load_config()
blocked_hosts: list[str] = get_blocked_hosts(config)
hosts_manager = HostsManager()
dns_server_running: bool = False

# Apply initial hosts file state based on config
def _apply_initial_hosts_state() -> None:
    for group_name, group in config.groups.items():
        hosts_manager.update_group(group.hosts, enable=group.on)
_apply_initial_hosts_state()


def clear_console() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def print_header(title: str) -> None:
    print("=" * 60)
    print(f"{title:^60}")
    print("=" * 60)
    print()


def print_status(text: str, status: str) -> None:
    """Print status with color coding"""
    colors = {
        "info": "\033[94m",      # Blue
        "success": "\033[92m",   # Green
        "warning": "\033[93m",   # Yellow
        "error": "\033[91m",     # Red
        "reset": "\033[0m"       # Reset
    }
    color = colors.get(status.lower(), colors["info"])
    reset = colors["reset"]
    print(f"{color}[{status.upper()}]{reset} {text}")


def log(msg: str) -> None:
    logger.info(msg)


def get_forwarders() -> list[str]:
    try:
        import pythoncom
        import wmi
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
    except ImportError:
        return ["8.8.8.8", "1.1.1.1"]


def menu_presets() -> None:
    global blocked_hosts, config

    while True:
        clear_console()
        print("=== RUBlocker84 Presets ===\n")
        groups = config.groups
        if not groups:
            print("No presets found!")
            input("\nPress Enter to return...")
            return

        for i, (name, group) in enumerate(groups.items(), start=1):
            status_str = "\033[92mON\033[0m" if group.on else "\033[91mOFF\033[0m"
            print(f"{i}. {name} - {group.description} [{status_str}]")
        print("0. Back to main menu")

        choice = input("\nEnter preset number to toggle or 0 to go back: ").strip()
        if choice == "0":
            break

        try:
            idx = int(choice) - 1
            if idx < 0 or idx >= len(groups):
                raise ValueError()
        except ValueError:
            print("Invalid choice, try again...")
            time.sleep(1)
            continue

        name = list(groups.keys())[idx]
        group = groups[name]
        group.on = not group.on
        save_config(config)
        status_str = "ON" if group.on else "OFF"
        print(f"\nPreset '{name}' toggled {status_str}")
        log(f"Preset {name} toggled {status_str}")
        blocked_hosts = get_blocked_hosts(config)
        hosts_manager.update_group(group.hosts, enable=group.on)
        time.sleep(2)


def install_scheduler_task() -> None:
    task_name = "RUBlocker84Task"
    rusvc_path = os.path.join(os.path.dirname(sys.argv[0]) or ".", "rusvc.exe")

    check_cmd = ["schtasks", "/Query", "/TN", task_name]
    exists = subprocess.run(check_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

    if exists:
        print(f"Task '{task_name}' already exists. Removing...")
        subprocess.run(["schtasks", "/Delete", "/F", "/TN", task_name], stdout=subprocess.DEVNULL)
        print("Existing task removed. Exiting without creating a new one.")
        time.sleep(1)
        return

    create_cmd = [
        "schtasks", "/Create", "/TN", task_name,
        "/TR", f'"{rusvc_path}"', "/SC", "ONLOGON",
        "/DELAY", "0001:00", "/RL", "HIGHEST", "/F"
    ]

    result = subprocess.run(create_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode == 0:
        print(f"Task '{task_name}' created successfully.")
    else:
        print("Failed to create task:")
        print(result.stderr)


def start_rusvc_background() -> None:
    """Start rusvc.exe as a background process (hidden window)."""
    rusvc_path = os.path.join(os.path.dirname(sys.argv[0]) or ".", "rusvc.exe")
    if not os.path.exists(rusvc_path):
        print_status("rusvc.exe not found in the same directory as rucli.exe", "error")
        return
    try:
        # Use CREATE_NO_WINDOW to hide console window
        subprocess.Popen([rusvc_path], creationflags=subprocess.CREATE_NO_WINDOW,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print_status("Background service started (rusvc.exe)", "success")
    except Exception as e:
        print_status(f"Failed to start background service: {e}", "error")


def is_rusvc_running() -> bool:
    """Check if rusvc.exe process is currently running."""
    try:
        # Use tasklist to check for the process
        result = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq rusvc.exe"],
            capture_output=True,
            text=True,
            check=False
        )
        return "rusvc.exe" in result.stdout
    except Exception:
        return False


def kill_rusvc_process() -> None:
    """Kill the rusvc.exe process if it's running."""
    try:
        # Use taskkill to forcefully terminate rusvc.exe
        result = subprocess.run(
            ["taskkill", "/F", "/IM", "rusvc.exe"],
            capture_output=True,
            text=True,
            check=False
        )
        if result.returncode == 0:
            print_status("Successfully terminated rusvc.exe process", "success")
        elif "NOT FOUND" in result.stderr or "no running instances" in result.stderr.lower():
            print_status("No rusvc.exe process found running", "info")
        else:
            print_status(f"Failed to terminate rusvc.exe: {result.stderr}", "error")
    except Exception as e:
        print_status(f"Error while trying to kill rusvc.exe: {e}", "error")


def main_menu() -> None:
    global blocked_hosts, config

    while True:
        clear_console()
        print_header("RUBlocker84 - Tracker Blocker")
        print_status("Choose an option:", "info")
        print("1. Presets")
        print("2. Show active blocked hosts")
        print("3. Install scheduler task")

        # Check if rusvc is running for menu option 4
        rusvc_status = "RUNNING" if is_rusvc_running() else "STOPPED"
        rusvc_color = "success" if is_rusvc_running() else "warning"
        print(f"4. Start background service (rusvc.exe) [{rusvc_status}]")
        print("5. Kill service process (rusvc.exe)")
        print("0. Exit")

        choice = input("\n>>> ").strip()

        if choice == "1":
            menu_presets()
        elif choice == "2":
            clear_console()
            print_header("Active Blocked Hosts")
            if blocked_hosts:
                for h in blocked_hosts:
                    print(f" - {h}")
                print_status(f"Total: {len(blocked_hosts)} hosts blocked", "success")
            else:
                print_status("No hosts currently blocked", "warning")
            input("\nPress Enter to return...")
        elif choice == "3":
            install_scheduler_task()
            input("Press Enter to continue...")
        elif choice == "4":
            start_rusvc_background()
        elif choice == "5":
            kill_rusvc_process()
            input("\nPress Enter to continue...")
        elif choice == "0":
            print_status("Goodbye!", "success")
            break
        else:
            print_status("Invalid choice, try again...", "error")
            time.sleep(1)


if __name__ == "__main__":
    main_menu()