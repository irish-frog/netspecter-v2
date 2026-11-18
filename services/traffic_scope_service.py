"""Define which destinations belong to the site's internal network."""

import ipaddress
import re


def internal_ipv4_networks(config):
    prefix = str(config.get("lan_prefix") or "192.168.1.").strip()
    if prefix.endswith("."):
        prefix += "0/24"
    elif "/" not in prefix:
        prefix += "/24"
    extra = config.get("internal_networks", [])
    if isinstance(extra, str):
        extra = re.split(r"[,\s]+", extra.strip())
    lan = ipaddress.ip_network(prefix, strict=False)
    if lan.version != 4 or lan.num_addresses > 1024:
        raise ValueError("LAN Prefix must be an IPv4 network of /22 or smaller")
    networks = [lan]
    for value in extra or []:
        if not str(value).strip():
            continue
        network = ipaddress.ip_network(str(value).strip(), strict=False)
        if network.version != 4:
            raise ValueError("Internal networks must use IPv4 CIDRs")
        if network.prefixlen == 0:
            raise ValueError("An internal network cannot cover the entire internet")
        networks.append(network)
    return tuple(ipaddress.collapse_addresses(networks))


def is_internal_destination(destination, networks):
    address = ipaddress.ip_address(str(destination))
    return any(address in network for network in networks)
