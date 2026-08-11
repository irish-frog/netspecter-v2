# Bridge Configuration

NetSpecter is installed inline as a transparent bridge. It needs two physical Ethernet ports:

- router-facing NIC
- LAN-facing NIC

NetSpecter does not replace the router or firewall.

## Supported Layout

```text
Internet -> Router -> NetSpecter bridge -> Switch -> Client devices
```

Example:

```text
Router ---- enp1s0 | br0 | enp2s0 ---- Switch
```

## Static Management IP On The Bridge

Bridge changes can disconnect SSH. Use local console access if possible.

Example `/etc/network/interfaces`:

```text
auto lo
iface lo inet loopback

auto br0
iface br0 inet static
    address 192.168.1.10/24
    gateway 192.168.1.1
    dns-nameservers 192.168.1.1
    bridge_ports enp1s0 enp2s0
    bridge_stp off
    bridge_fd 0
    bridge_maxwait 0

iface enp1s0 inet manual
iface enp2s0 inet manual
```

Change IPs and interface names before saving. The management IP belongs on `br0`, not on physical bridge ports.

## Verify

```bash
ip -br addr show br0
bridge link
ip route
ping -c 3 1.1.1.1
```

## Loop/STP Warning

Both physical ports bridged with STP off is safe only when the appliance is truly inline:

```text
router/firewall -> NetSpecter port A -> NetSpecter port B -> switch/LAN
```

It is dangerous if both ports connect back into the same switch/LAN fabric.

Immediate protective test if a loop is suspected:

```bash
ip link set br0 type bridge stp_state 1
cat /sys/class/net/br0/bridge/stp_state
bridge link
```

To make STP persistent, first identify the network config source:

```bash
grep -R "br0\|enp11s0f0\|enp11s0f1\|stp" /etc/network /etc/systemd/network /etc/netplan 2>/dev/null
```

Do not blindly patch networking without knowing which system controls it.
