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


# Destinations that cannot represent public internet usage. Keep bridge and flow scope aligned.
NON_INTERNET_V4 = tuple(ipaddress.ip_network(value) for value in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/29", "192.0.0.8/32", "192.0.0.11/32", "192.0.0.12/30",
    "192.0.0.16/28", "192.0.0.32/27", "192.0.0.64/26", "192.0.0.128/25", "192.0.2.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
))


def accounting_destinations(config):
    return tuple(ipaddress.collapse_addresses((*internal_ipv4_networks(config), *NON_INTERNET_V4)))


def accounting_clients(config):
    hosts=set()
    for network in internal_ipv4_networks(config):
        # Large routed networks are exclusions, not millions of counter rules.
        if network.num_addresses<=1024:
            hosts.update(str(address) for address in network.hosts())
    if len(hosts)>4096:
        raise ValueError("Configured client networks exceed the 4096-address accounting limit")
    return hosts
