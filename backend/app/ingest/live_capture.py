"""Live packet sniffer for port 53 with Npcap detection and graceful degradation.

Provides non-blocking live packet capture using Scapy AsyncSniffer, with
explicit detection and error messaging when Npcap is missing on Windows.
"""

from typing import Callable, Optional, Dict, Any
import threading
import time
import sys
from scapy.all import AsyncSniffer, DNS, DNSQR, IP, IPv6
from backend.app.ingest.pcap_parser import QTYPE_MAP


class LiveSnifferManager:
    """Manages active live DNS sniffing session on port 53."""

    def __init__(self):
        self.sniffer: Optional[AsyncSniffer] = None
        self.is_capturing: bool = False
        self.interface: str = "default"
        self.packets_captured: int = 0
        self.incidents_detected: int = 0
        self.start_time: Optional[float] = None
        self.error_message: Optional[str] = None
        self.packet_callback: Optional[Callable[[Dict[str, Any]], None]] = None
        self._lock = threading.Lock()

    def check_npcap_availability(self) -> bool:
        """Check if Npcap / pcap capture capability is present on Windows."""
        if sys.platform == "win32":
            try:
                from scapy.arch.windows import get_windows_if_list
                interfaces = get_windows_if_list()
                if not interfaces:
                    return False
            except Exception:
                return False
        return True

    def _packet_handler(self, pkt):
        """Internal callback executed per captured packet."""
        with self._lock:
            self.packets_captured += 1

        if not pkt.haslayer(DNS):
            return

        dns = pkt.getlayer(DNS)
        if dns.qr == 0 and dns.qdcount > 0 and pkt.haslayer(DNSQR):
            dnsqr = pkt.getlayer(DNSQR)

            src_ip = "0.0.0.0"
            dst_ip = "0.0.0.0"
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
            elif pkt.haslayer(IPv6):
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst

            raw_qname = dnsqr.qname
            if isinstance(raw_qname, bytes):
                qname_str = raw_qname.decode("utf-8", errors="ignore").rstrip(".")
            else:
                qname_str = str(raw_qname).rstrip(".")

            qtype_int = int(dnsqr.qtype)
            qtype_str = QTYPE_MAP.get(qtype_int, f"TYPE{qtype_int}")

            record = {
                "timestamp": float(pkt.time if hasattr(pkt, "time") else time.time()),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "qname": qname_str,
                "qtype": qtype_str,
                "qclass": "IN",
                "rcode": "NOERROR",
                "payload_len": len(pkt),
                "is_synthetic": False,
            }

            if self.packet_callback:
                try:
                    self.packet_callback(record)
                except Exception:
                    pass

    def start_capture(
        self,
        interface: Optional[str] = None,
        callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> bool:
        """Start live packet capture on port 53.

        Returns:
            True if capture started successfully, False if failed.
        """
        with self._lock:
            if self.is_capturing:
                return True

            self.error_message = None
            if sys.platform == "win32" and not self.check_npcap_availability():
                self.error_message = (
                    "Live packet capture requires Npcap on Windows. "
                    "Please install Npcap with 'WinPcap API Compatibility' mode from https://npcap.com/"
                )
                return False

            try:
                filter_str = "udp port 53 or tcp port 53"
                sniffer_kwargs = {
                    "filter": filter_str,
                    "prn": self._packet_handler,
                    "store": False,
                }
                if interface and interface != "default":
                    sniffer_kwargs["iface"] = interface

                self.sniffer = AsyncSniffer(**sniffer_kwargs)
                self.sniffer.start()

                self.is_capturing = True
                self.interface = interface or "default"
                self.packets_captured = 0
                self.incidents_detected = 0
                self.start_time = time.time()
                self.packet_callback = callback
                return True

            except Exception as e:
                self.is_capturing = False
                self.error_message = (
                    f"Failed to start live capture: {str(e)}. "
                    "Ensure Npcap/WinPcap is installed and program has elevated administrator privileges."
                )
                return False

    def stop_capture(self) -> bool:
        """Stop active live packet capture session."""
        with self._lock:
            if not self.is_capturing:
                return True

            if self.sniffer:
                try:
                    self.sniffer.stop()
                except Exception:
                    pass
                self.sniffer = None

            self.is_capturing = False
            return True

    def get_status(self) -> Dict[str, Any]:
        """Return current live sniffer status dictionary."""
        with self._lock:
            return {
                "is_capturing": self.is_capturing,
                "interface": self.interface,
                "packets_captured": self.packets_captured,
                "incidents_detected": self.incidents_detected,
                "start_time": self.start_time,
                "npcap_available": self.check_npcap_availability(),
                "error_message": self.error_message,
            }


# Singleton manager instance
live_sniffer = LiveSnifferManager()
