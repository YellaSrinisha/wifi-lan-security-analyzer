import socket
import ipaddress
from typing import Optional

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


def get_network_interfaces() -> list[dict]:
    """Return a list of local IPv4 network interfaces using psutil."""
    if not PSUTIL_AVAILABLE:
        return []
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        interfaces = []
        for iface_name, addr_list in addrs.items():
            for addr in addr_list:
                # AF_INET = 2 (IPv4)
                if addr.family == socket.AF_INET:
                    is_up: Optional[bool] = None
                    if iface_name in stats:
                        is_up = stats[iface_name].isup

                    broadcast: Optional[str] = None
                    if addr.broadcast:
                        broadcast = addr.broadcast
                    elif addr.address and addr.netmask:
                        try:
                            network = ipaddress.IPv4Network(
                                f"{addr.address}/{addr.netmask}", strict=False
                            )
                            broadcast = str(network.broadcast_address)
                        except Exception:
                            pass

                    interfaces.append({
                        "name": iface_name,
                        "ip_address": addr.address or None,
                        "netmask": addr.netmask or None,
                        "broadcast": broadcast,
                        "is_up": is_up,
                    })
        return interfaces
    except Exception:
        return []
