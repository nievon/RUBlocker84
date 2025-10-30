"""
RUBlocker84 Background DNS Service
"""

import sys
import threading
import time
import os
import signal
from core import (
    log,
    blocked_hosts,
    config,
    backup_and_set_local_dns,
    restore_dns,
    dns_server,
    LOCAL_IP,
    get_adapters_dns,
)

stop_event = threading.Event()

def run_dns():
    try:
        adapters = backup_and_set_local_dns()
        forwarders = []
        for dns_list in adapters.values():
            forwarders.extend(dns_list)
        forwarders = list(filter(lambda x: x != LOCAL_IP, forwarders))
        dns_server(forwarders, stop_event)
    finally:
        restore_dns()

def signal_handler(sig, frame):
    stop_event.set()
    time.sleep(1)
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    t = threading.Thread(target=run_dns, daemon=True)
    t.start()

    try:
        while not stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        stop_event.set()
    finally:
        restore_dns()
