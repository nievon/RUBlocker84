"""
RUBlocker84 CLI Application.

Provides interactive command-line interface for managing the tracker blocker.
"""

import os
import subprocess
import sys
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
    Config, load_config, save_config, get_blocked_hosts
)
from blocker.hosts import HostsManager

# Global state
config: Config = load_config()
blocked_hosts: list[str] = get_blocked_hosts(config)
hosts_manager = HostsManager()

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


def show_unlock_animation() -> None:
    """Show a full-screen ASCII animation of a lock opening."""
    lock_closed = """                                                                                                
                                     .:=#%@@@@@@@@@@@@@@@@%#=:.                                     
                              ..:*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*:..                              
                          .:+@@@@@@@@%+-..                ..-+%@@@@@@@@+:.                          
                       :*@@@@@@%*-.                              .:+%@@@@@@*:                       
                    -%@@@@@%=.                                        .=%@@@@@%=                    
                .=@@@@@@+.                                                .+@@@@@@=.                
             .=@@@@@%-                     .-*@@@@@@@@*-.                     -%@@@@@=.             
           :%@@@@%-.                    :#@@@@@@@@@@@@@@@@#:                    .-%@@@@%:           
        .*@@@@@=.                     :@@@@@@@@@@@@@@@@@@@@@@:                     .-@@@@@*.        
      .%@@@@#                        *@@@@@@@@@@@@@@@@@@@@@@@@#                        *@@@@%.      
    :%@@@@-.                       .@@@@@@@@@@@@@@@@@@@@@@@@@@@@.                       .-@@@@@:    
   -@@@%:                          +@@@@@@@@@@@@@@@@@@@@@@@@@@@@+                          :%@@@-   
  .@@@%.                          .@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.                          .%@@@.  
  -@@@-                           .@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@:                           -@@@-  
  .@@@%.                          .@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.                          .%@@@.  
   -@@@%:                          +@@@@@@@@@@@@@@@@@@@@@@@@@@@@+                          :%@@@-   
    :%@@@@-.                       .@@@@@@@@@@@@@@@@@@@@@@@@@@@@.                       .-@@@@@:    
      .%@@@@#                        *@@@@@@@@@@@@@@@@@@@@@@@@#                        *@@@@%.      
        .*@@@@@=.                     :@@@@@@@@@@@@@@@@@@@@@@:                     .-@@@@@*.        
           :%@@@@%-.                    :#@@@@@@@@@@@@@@@@#:                    .-%@@@@%:           
             .=@@@@@%-                     .-*@@@@@@@@*-.                     -%@@@@@=.             
                .=@@@@@@+.                                                .+@@@@@@=.                
                    -%@@@@@%=.                                        .=%@@@@@%=                    
                       :*@@@@@@%*-.                              .:+%@@@@@@*:                       
                          .:+@@@@@@@@%+-..                ..-+%@@@@@@@@+:.                          
                              ..:*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*:..                              
                                     .:=#%@@@@@@@@@@@@@@@@%#=:.                                     
    """

    lock_opening = """          
                                                                                .*@@@:              
                                                                              .*@@@@@=              
                                                                            .*@@@@@#.               
                                                                          .*@@@@@*.                 
                                      .-#%@@@@@@@@@@@@@@@@%%+:.         .*@@@@@*.                   
                               ..=@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#-. .*@@@@@*.                     
                          ..=%@@@@@@@%*=:.                 .:+#@@@+ .*@@@@@*.                       
                       .=%@@@@@@#=..                              .*@@@@@+..:                       
                    .#@@@@@@*:.                                 .#@@@@@+. +@@@@=                    
                 .#@@@@@%:                                    .#@@@@@+    .=@@@@@@+.                
              :#@@@@@#.                    .:+%@@@@@@@#=:.  .#@@@@@+.         -%@@@@@=.             
           .+@@@@@+.                    .*@@@@@@@@@@@@@@= .#@@@@@+.             .-#@@@@%-           
         :%@@@@#.                     .%@@@@@@@@@@@@@@=..%@@@@@+.                   -@@@@@#.        
       =@@@@@-                       -@@@@@@@@@@@@@@- .%@@@@@+                         *@@@@%.      
     =@@@@#.                        =@@@@@@@@@@@@@= .#@@@@@+..*@.                        -@@@@%:    
   .#@@@*.                         :@@@@@@@@@@@@= .#@@@@@+..*@@@#.                         :%@@@-   
   -@@@=                          .*@@@@@@@@@@= .#@@@@@=..*@@@@@@.                          .#@@@.  
   *@@@.                          .#@@@@@@@@- .%@@@@@=  *@@@@@@@@:                           -@@@-  
   -@@@=                          .*@@@@@@-..#@@@@@= .*@@@@@@@@@@.                          .#@@@.  
   .#@@@*.                         :@@@@- .#@@@@@=..*@@@@@@@@@@@#.                         :%@@@-   
     =@@@@#.                        =@- .%@@@@@-..#@@@@@@@@@@@@@.                        -@@@@%:    
       =@@@@@-                        .@@@@@@-  #@@@@@@@@@@@@@@.                       *@@@@%.      
         :%@@@@#.                   .@@@@@@= .#@@@@@@@@@@@@@@+                      -@@@@@#.        
           .+@@@@@+.              .%@@@@@=..#@@@@@@@@@@@@@%-.                   .-#@@@@%-           
              :#@@@@@#.         .%@@@@@-.  .:+%@@@@@@@#=:                     -%@@@@@=.             
                 .#@@@@@%:    .%@@@@@-.                                   .=@@@@@@+.                
                    .#@@@@: :%@@@@@-                                  .-%@@@@@@=                    
                       .: :%@@@@@-                               .:+%@@@@@@*:                       
                        .%@@@@@-..%@@%*=:.                 .:+#@@@@@@@@*:.                          
                      .@@@@@@:. .=@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#-..                              
                    :@@@@@@-          .-#%@@@@@@@@@@@@@@@@%%+:.                                     
                  :@@@@@@-                                                                          
                :%@@@@@-                                                                            
               #@@@@@:.                                                                             
               +@@@:                                                                                
    """

    freedom = """

          ✨ ✨ ✨
       ✨  FREE  ✨
          ✨ ✨ ✨

    """

    frames = [lock_closed, lock_opening, freedom]
    durations = [0.6, 0.6, 0.6]

    sys.stdout.write("\033[?25l")
    sys.stdout.flush()

    try:
        for i, frame in enumerate(frames):
            clear_console()
            try:
                cols, rows = os.get_terminal_size()
            except OSError:
                cols, rows = 80, 24

            frame_lines = frame.strip('\n').splitlines()
            frame_height = len(frame_lines)

            # Vertical centering
            vpad = (rows - frame_height) // 2
            for _ in range(max(0, vpad)):
                print()

            # Horizontal centering
            max_width = max(len(line) for line in frame_lines) if frame_lines else 0
            for line in frame_lines:
                if len(line) < cols:
                    hpad = (cols - len(line)) // 2
                    print(' ' * hpad + line)
                else:
                    print(line)

            time.sleep(durations[i])
    finally:
        sys.stdout.write("\033[?25h")
        sys.stdout.flush()


def menu_presets() -> None:
    """Menu for toggling preset groups."""
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
        if group.on:  # Show unlock animation when enabling (unlocking)
            show_unlock_animation()
        log(f"Preset {name} toggled {status_str}")
        blocked_hosts = get_blocked_hosts(config)
        hosts_manager.update_group(group.hosts, enable=group.on)
        time.sleep(1)


def main_menu() -> None:
    """Main application menu."""
    global blocked_hosts, config

    while True:
        clear_console()
        print_header("RUBlocker84 - Tracker Blocker")
        print_status("Choose an option:", "info")
        print("1. Presets")
        print("2. Show active blocked hosts")
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
        elif choice == "0":
            print_status("Goodbye!", "success")
            break
        else:
            print_status("Invalid choice, try again...", "error")
            time.sleep(1)


if __name__ == "__main__":
    main_menu()