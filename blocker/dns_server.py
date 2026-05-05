"""DNS server module for RUBlocker84."""

import logging
import select
import socket
import threading
from typing import Optional

from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A

logger = logging.getLogger(__name__)

LOCAL_IP = "127.0.1.10"
DNS_PORT = 53


class DNSServer:
    def __init__(self, blocked_hosts: list[str], forwarders: list[str]):
        self.blocked_hosts = blocked_hosts
        self.forwarders = forwarders
        self.sock: Optional[socket.socket] = None
        self.stop_event = threading.Event()
        self._lock = threading.Lock()

    def update_blocked_hosts(self, hosts: list[str]) -> None:
        with self._lock:
            self.blocked_hosts = hosts

    def _handle_client(self, data: bytes, addr: tuple) -> None:
        try:
            request = DNSRecord.parse(data)
            qname = str(request.q.qname).rstrip(".")

            with self._lock:
                blocked = self.blocked_hosts

            if any(qname.endswith(h) for h in blocked):
                reply = DNSRecord(
                    DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q
                )
                reply.add_answer(RR(qname, QTYPE.A, rdata=A("0.0.0.0"), ttl=0))
                self.sock.sendto(reply.pack(), addr)
                logger.info(f"BLOCKED {qname} ({addr[0]}:{addr[1]})")
            else:
                self._forward_query(data, addr)
        except Exception as e:
            logger.error(f"Error handling {addr}: {e}")

    def _forward_query(self, data: bytes, addr: tuple) -> None:
        for forward in self.forwarders:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as forward_sock:
                    forward_sock.settimeout(2)
                    forward_sock.sendto(data, (forward, DNS_PORT))
                    resp, _ = forward_sock.recvfrom(512)
                    self.sock.sendto(resp, addr)
                    return
            except Exception:
                continue

    def start(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((LOCAL_IP, DNS_PORT))
        self.sock.setblocking(False)
        logger.info(f"DNS server running on {LOCAL_IP}:{DNS_PORT}")

        while not self.stop_event.is_set():
            ready = select.select([self.sock], [], [], 1.0)
            if ready[0]:
                try:
                    data, addr = self.sock.recvfrom(512)
                    threading.Thread(
                        target=self._handle_client,
                        args=(data, addr),
                        daemon=True,
                    ).start()
                except Exception as e:
                    logger.error(f"Server error: {e}")

    def stop(self) -> None:
        self.stop_event.set()
        if self.sock:
            self.sock.close()
            self.sock = None
        logger.info("DNS server stopped")