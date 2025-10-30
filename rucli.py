"""
RUBlocker84 CLI
"""

import sys
import threading
import time
import os
import subprocess
from core import (
    log, blocked_hosts, config, load_config, save_config, get_blocked_hosts,
    backup_and_set_local_dns, update_kernel_hosts,
    restore_dns, dns_server, HAS_PYWIN32
)

def clear_console():
    import os
    os.system("cls" if os.name == "nt" else "clear")

def menu_presets():
    global blocked_hosts, config

    while True:
        clear_console()
        print("=== RUBlocker84 Presets ===\n")
        groups = config.get("groups", {})
        if not groups:
            print("No presets found!")
            input("\nPress Enter to return...")
            return

        # All configured presets
        for i, (name, group) in enumerate(groups.items(), start=1):
            status = group.get("on", False)
            status_str = "\033[92mON\033[0m" if status else "\033[91mOFF\033[0m"
            print(f"{i}. {name} - {group.get('description')} [{status_str}]")
        print("0. Back to main menu")

        choice = input("\nEnter preset number to toggle or 0 to go back: ").strip()
        if choice == "0":
            break

        if not choice.isdigit() or int(choice) < 1 or int(choice) > len(groups):
            print("Invalid choice, try again...")
            time.sleep(1)
            continue

        # Toggle preset
        idx = int(choice) - 1
        name = list(groups.keys())[idx]
        group = groups[name]
        group["on"] = not group.get("on", False)
        save_config(config)
        status_str = "ON" if group["on"] else "OFF"
        print(f"\nPreset '{name}' toggled {status_str}")
        log(f"Preset {name} toggled {status_str}")
        blocked_hosts = get_blocked_hosts(config)
        update_kernel_hosts(name, enable=group["on"])
        time.sleep(4)  # Pause before refreshing

def install_scheduler_task():
    task_name = "RUBlocker84Task"
    rusvc_path = os.path.join(os.path.dirname(sys.argv[0]), "rusvc.exe")
    check_cmd = ["schtasks", "/Query", "/TN", task_name]
    exists = subprocess.run(check_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

    if exists:
        print(f"Task '{task_name}' already exists. Removing...")
        subprocess.run(["schtasks", "/Delete", "/F", "/TN", task_name], stdout=subprocess.DEVNULL)
        print("Existing task removed. Exiting without creating a new one.")
        time.sleep(1)
        return

    create_cmd = [
        "schtasks",
        "/Create",
        "/TN", task_name,
        "/TR", f'"{rusvc_path}"',
        "/SC", "ONLOGON",
        "/DELAY", "0001:00",   
        "/RL", "HIGHEST",       
        "/F"                    
    ]

    result = subprocess.run(create_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode == 0:
        print(f"Task '{task_name}' created successfully.")
    else:
        print("Failed to create task:")
        print(result.stderr)


def main_menu():
    global blocked_hosts, config
    while True:
        clear_console()
        print("=== RUBlocker84 ===\n")
        print("1. Presets")
        print("2. Show active blocked hosts")
        print("3. Install and start service")
        print("4. Run local DNS (CLI)")
        print("0. Exit")

        choice = input("\n>>> ").strip()

        if choice == "1":
            menu_presets()
        elif choice == "2":
            clear_console()
            print("=== Active Blocked Hosts ===\n")
            for h in blocked_hosts:
                print(" -", h)
            input("\nPress Enter to return...")
        elif choice == "3":
            install_scheduler_task()
            start_now = input("Start now? [y/N]: ").strip().lower()
            if start_now == "y":
                subprocess.run(["schtasks", "/Run", "/TN", "RUBlocker84Task"])
                print("Task started.")
                time.sleep(1)


        elif choice == "4":
            adapters = backup_and_set_local_dns()
            forwarders = []
            for dns_list in adapters.values():
                forwarders.extend(dns_list)
            forwarders = list(filter(lambda x: x != LOCAL_IP, forwarders))
            stop_event = threading.Event()
            try:
                dns_server(forwarders, stop_event)
            except KeyboardInterrupt:
                stop_event.set()
                restore_dns()
                log("Exit.")
                sys.exit(0)
        elif choice == "0":
            restore_dns()
            break
        else:
            print("Invalid choice, try again...")
            time.sleep(1)


if __name__ == "__main__":
    main_menu()
