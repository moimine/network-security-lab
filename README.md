# Network & Cybersecurity Homelab

Network, virtualization & cybersecurity homelab: DHCP, DNS, routing, VLAN segmentation, firewall, Active Directory, IDS/SIEM, built step by step from scratch.

## Summary

- [x] [Phase 0 - Setup](#phase-0--setup)
- [x] [Phase 1 - First virtual network](#phase-1--first-virtual-network)
- [x] [Phase 2 - Network servers (DHCP/DNS)](#phase-2--network-servers)
- [ ] [Phase 3 - Routing](#phase-3--routing)
- [ ] [Phase 4 - Firewall](#phase-4--firewall)
- [ ] [Phase 5 - Active Directory](#phase-5--active-directory)
- [ ] [Phase 6 - Cyber Blue Team (detection)](#phase-6--cyber-blue-team-detection)
- [ ] [Phase 7 - Cyber Red Team (attack)](#phase-7--cyber-red-team-attack)
- [ ] [Phase 8 - Virtual network segmentation](#phase-8--virtual-network-segmentation)
- [ ] [Phase 9 - Moving to real hardware](#phase-9--moving-to-real-hardware)
- [ ] [Phase 10 - HID injection](#phase-10--hid-injection)

---

# Phase 0 - Setup

**Goal:** understand the environment before building anything.

**Tools and hardware:** Debian PC, Incus, Wireshark, tcpdump, systemd-networkd, systemd-resolved.

## Step 0.1 - Understanding the host machine

Basic exploration of the host's network configuration: interface, IP address, gateway, DNS.

**What I observed and understood:**
- The difference between the network address (`.0`), the broadcast address (the last address of the block, `.255` for a `/24`), and the usable host addresses.
- Name resolution goes through `systemd-resolved`, which forwards requests to whichever DNS server is configured.
- The gateway is usually, by convention, the first address of the network (`.1`) - but that's just a convention, not a rule.
- The difference between a `scope link` route (directly reachable local network) and a `via` route (reachable through a gateway).

Key commands:
```bash
ip address show
ip route show
resolvectl status
```

![Host network configuration output](assets/config-net-hote.png)

## Step 0.2 - Understanding Incus

**Goal:** get familiar with Incus's core concepts before creating any instance.

**Installation and initialization:**
```bash
apt install incus
incus admin init
```

**Concepts covered:**
- **Storage pool vs storage volume** : the pool is the total physical space available to all instances; a volume is the portion of that space dedicated to a specific instance.
- **Profile** : a reusable configuration template, applied to one or more instances to avoid repeating the same settings on every creation.
- **Project** : an isolation space, used to keep groups of instances, networks, and profiles separate within a single Incus host.
- **Network** : a managed bridge that instances connect to in order to communicate with each other and the outside world. By default, `incus admin init` creates one such bridge (`incusbr0`), used automatically unless another network is specified.
- **Built-in network stack** : Incus runs a `dnsmasq` service by default, acting as both DHCP and DNS server on every network it creates.
- **Hypervisor** : Incus VMs run on KVM, the Linux kernel's native hypervisor.

**Commands used to explore these concepts:**
```bash
incus storage list
incus project list
incus network list
incus profile list
```
Storage list :

![Output of incus storage list](assets/incus-storage-list.png)

Network list :

![Output of network list](assets/incus-network-list.png)

---

# Phase 1 - First virtual network

**Goal:** understand how machines communicate with each other.

## Step 1.1 - Create a network

```text
Name   : lab-net
Subnet : 10.10.1.0/24
```

## Step 1.2 - First container (`debian1`)

```bash
incus shell debian1
ip a
```

![debian1 IPv4 address](assets/ipa-deb1.png)

## Step 1.3 - Second container (`debian2`)

```bash
incus shell debian2
ip a
```

![debian2 IPv4 address](assets/ipa-deb2.png)

## Observations: DHCP, DNS, ARP, ICMP and NAT

### DHCP

- Exchange between the DHCP server (`dnsmasq`, built into Incus) and the machines on `lab-net`, for IP address assignment following the DORA cycle: Discover, Offer, Request, Acknowledge.
- The protocol uses two UDP ports:
  - port 67 (`bootps`): the **server** listens here (receives Discover and Request);
  - port 68 (`bootpc`): the **client** listens here (receives Offer and Acknowledge).

```bash
sudo tcpdump -i lab-net port 67 or port 68 -vvv
```

![DORA exchange](assets/dora.png)

### DNS

- Name resolution, required to reach the internet.
- Distinction between the local resolver (the `systemd-resolved` stub) and authoritative/recursive DNS servers.
- The protocol uses port 53: UDP by default, TCP for larger responses and zone transfers.

```bash
nslookup google.com
host google.com
dig google.com
```

### ARP

- Capturing ARP frames (`who-has` / `is-at`) between two test containers.
- Different behavior between `arping` and `ping` regarding the kernel's neighbor cache: `arping` stays strictly at layer 2 and doesn't update the neighbor cache, while `ping` triggers a normal ARP resolution and creates a `REACHABLE` entry.

```bash
incus exec debian1 -- arping -c 2 debian2
incus exec debian1 -- ip neigh show
```

![ARP exchange](assets/arping.png)

After these exchanges, each machine caches its peer's MAC address:

![ARP cache](assets/cache-arp.png)

### ICMP

- ICMP Echo Request / Echo Reply sequences.
- The `Destination Host Unreachable` case, generated locally when ARP resolution fails.
- How TTL works, and how `traceroute` makes use of it.

```bash
incus exec debian1 -- ping debian2
```

![ICMP (ping) exchange](assets/ping.png)

```bash
incus exec debian1 -- ip route
incus exec debian1 -- traceroute debian2
incus exec debian1 -- traceroute google.com
```

![Routing table and hops to destination](assets/routage-deb1.png)

### NAT

- Address translation: containers (private IP `10.10.1.x`) reach the internet masked behind the host machine's IP (`192.168.1.32`).
- Verified by comparing two captures, before and after translation (bridge interface, then the host's outbound interface).

```bash
incus exec debian1 -- ping -c 2 8.8.8.8
```

On the host, before translation (the container's IP is visible):

```bash
sudo tcpdump -i lab-net icmp -n
```

![Capture before NAT](assets/avant-nat.png)

Then after translation (the host's IP is visible):

```bash
sudo tcpdump -i wlo1 icmp -n
```

![Capture after NAT](assets/apres-nat.png)

---

# Phase 2 - Network servers

**Goal:** set up DHCP and DNS so machines on the network can communicate without any manual configuration.

## Step 2.1 - Create a profile

```text
Name        : lab-limits
Description : baseline configuration shared by all containers/VMs used throughout the lab
```

This profile is shared across every instance in the lab: it's created in the `default` project and stays usable from other projects thanks to `features.profiles=false`.

```bash
incus profile create lab-limits
incus profile edit lab-limits < lab-limits.yaml
```

Config file: [`lab-limits.yaml`](configs/lab-limits.yaml)

## Step 2.2 - Create a project

```text
Name        : lab-srv
Description : groups the server machines (DHCP and DNS containers)
```

```bash
incus project create lab-srv --config features.profiles=false
incus project switch lab-srv
```

## Step 2.3 - Create a network

DHCP and DNS built into Incus are disabled on this network, so my own servers are the ones handling address assignment and name resolution.

```text
Name        : lab-net1
Description : lab network, 10.114.22.0/24, no built-in DHCP/DNS, domain homelab.local
```

```bash
incus network create lab-net1 ipv4.address=10.114.22.1/24 ipv4.nat=true ipv4.dhcp=false dns.mode=none dns.domain=lab.local
```

**Note:** the network lives in the `default` project and is shared with `lab-srv` (`features.networks=false`). Per-project network isolation in Incus requires OVN, which isn't needed here.

![lab-net1 network](assets/network-lab-net1.png)

## Step 2.4 - DHCP server

```text
Machine  : dhcp-server
Software : Kea DHCP
```

```bash
incus launch images:debian/13 dhcp-server --profile default --profile lab-limits --network lab-net1
apt install kea-dhcp4-server
```

### Container network configuration

`dhcp-server` uses a static IP address (`10.114.22.2`), configured with `systemd-networkd` in `/etc/systemd/network/eth0.network`. 

Config file: [`eth0.network`](configs/eth0.network)

![DHCP server IP address](assets/dhcp-server-ipa.png) 

### Kea configuration (`/etc/kea/kea-dhcp4.conf`)

**Note on future changes:** the `routers` option currently points to `10.114.22.1` (the `lab-net1` Incus bridge), used temporarily as the gateway. It will be updated to the virtual router's address once Phase 3 is done.

### Validation

```bash
kea-dhcp4 -t /etc/kea/kea-dhcp4.conf
sudo systemctl restart kea-dhcp4-server
sudo systemctl status kea-dhcp4-server
```

Full config file: [kea-dhcp4.conf](configs/kea-dhcp4.conf) 

**Tutorial used as a reference:** [Setting up a Kea DHCP server](https://www.it-connect.fr/linux-installer-et-configurer-un-serveur-dhcp-kea-sur-debian/)

---

## Step 2.5 - DNS server

```text
Machine  : dns-server
IP       : 10.114.22.3 (DHCP reservation by MAC address)
Software : bind9
Zone     : homelab.local
```

```bash
incus launch images:debian/13 dns-server --profile default --profile lab-limits --network lab-net1
apt install bind9 dnsutils
```

**DHCP result:** `dns-server` correctly receives its reserved address `10.114.22.3` from Kea, matching the configuration.

![DNS server validation](assets/validation-dns-server.png)

### Configuring bind9 (config files under `/etc/bind/`)

**First step:** configure bind9's general options in `/etc/bind/named.conf.options`.
Config used: [named.conf.options](configs/named.conf.options).

**Second step:** create and configure the forward and reverse DNS zones.

Zones are declared in `/etc/bind/named.conf.local`. This file tells bind9 which zones it's responsible for, and which zone files to use as the underlying database.

**Zone config file:** [named.conf.local](configs/named.conf.local).

Next, create and populate the zone files:
- Forward zone: name-to-IP records (e.g. `google.com` → `8.8.8.8`).
- Reverse zone: IP-to-name records (e.g. `8.8.8.8` → `google.com`).

- Forward zone file: [db.homelab.local](configs/db.homelab.local).
- Reverse zone file: [db.reverse.homelab.local](configs/db.reverse.homelab.local).

**Third step:** check the syntax of both zone files, then restart the BIND9 service:

```bash
named-checkzone homelab.local /etc/bind/db.homelab.local
named-checkzone 22.114.10.in-addr.arpa /etc/bind/db.reverse.homelab.local
sudo systemctl start bind9
sudo systemctl enable named.service
sudo systemctl status bind9
```

**Resolution test results with bind9:**

Resolution through the recursive resolver:

![google.com resolution result via bind9](assets/resolution-google.png)

Local reverse resolution:

![Reverse resolution result via bind9](assets/resolution_inverse.png)

**Tutorial used as a reference:** [Setting up a DNS server with BIND9](https://www.it-connect.fr/dns-avec-bind-9/)

---

## Step 2.6 - DHCP and DNS together

![DHCP and DNS servers](assets/serveurs.png)

---

# Phase 3 - Routing and VLAN Segmentation

**Goal:** understand how a router connects networks, and how VLANs, DHCP, DNS and NAT fit together around it, using Incus and Linux.

```text
Machine  : router1
OS       : Debian 13 (VM)
Network  : systemd-networkd
```

---

## Step 3.1 - Deploy the router VM

A router needs its own kernel and full control over its network stack, so `router1` is a VM rather than a container.

```bash
incus launch images:debian/13 router1 \
  --vm --project lab-srv \
  --profile default --profile lab-limits
```

It has two interfaces:

- **LAN** (`eth0`, `enp5s0` inside the VM): connected to `lab-net1`
- **WAN** (`eth1`, `enp6s0` inside the VM): connected to the outside world

### WAN interface: macvlan attempt (failed)

I first tried macvlan on the host's Wi-Fi card (`wlo1`), to give the router a real IP on the physical network, closer to what I will have on real hardware in Phase 9.

```bash
incus config device add router1 eth1 nic nictype=macvlan parent=wlo1
```

It failed. A packet capture on `wlo1` showed the router's DHCP Discover leaving the host, but no Offer ever came back. Wi-Fi (802.11) only allows one MAC address per radio association, so the router's virtual MAC could never complete its own DHCP negotiation.

![DORA failure](assets/dora-fail.png)

### WAN interface: Incus managed bridge (`incusbr0`)

I switched to `incusbr0`, the bridge Incus creates at `incus admin init`. It provides DHCP (through its built-in `dnsmasq`) and NAT toward the host's real interface.

```bash
incus config device remove router1 eth1
incus config device add router1 eth1 nic \
  nictype=bridged parent=incusbr0 --project lab-srv
incus network set incusbr0 ipv4.nat=true
incus network set lab-net1 ipv4.nat=false
```

NAT is disabled on `lab-net1` because `router1` handles NAT itself for its LAN. Keeping it on at both the bridge and the router would only add a redundant translation.

**Planned improvement:** retry macvlan over a wired Ethernet connection once I have a cable. Ethernet, unlike Wi-Fi, supports several MAC addresses on the same link, which should remove the limitation.

---

## Step 3.2 - Static IP on the LAN interface

At first the LAN was a flat `/24`. The router's LAN interface uses a static address, so it can act as a stable gateway instead of depending on DHCP itself (the DHCP server itself needs the router, so a DHCP-assigned router address would be circular).

```ini
# /etc/systemd/network/enp5s0.network
[Match]
Name=enp5s0

[Network]
Address=10.114.22.1/24
DHCP=false
```

Before this, `.1` had to be freed on the Incus side, since the bridge itself was holding it:

```bash
incus network set lab-net1 ipv4.address=10.114.22.254/24
```

![router1 LAN interface, static IP](assets/router1-ipa.png)

This flat configuration is replaced by the VLAN setup in Step 3.4.

---

## Step 3.3 - Make the bridge VLAN-aware

To carry several VLANs over one link, `lab-net1` has to behave like a managed switch. I enabled VLAN filtering on the host bridge and allowed the tagged VLANs on the router's LAN interface.

```bash
sudo ip link set dev lab-net1 type bridge vlan_filtering 1
incus config device set router1 eth0 vlan.tagged "10,20,30,40" --project lab-srv
```

Verification:

```bash
ip -d link show lab-net1
sudo bridge vlan show
```

![`Output of bridge vlan show`](assets/bridge-vlan.png)

### Making it persistent across host reboots (on the host)

The `ip link` change does not survive a reboot, so I wrapped it in a systemd service that waits for the bridge to exist.

- Service file: [`lab-net1-vlan.service`](configs/host/lab-net1-vlan.service)
- Wait-for-bridge override: [`override.conf`](configs/host/lab-net1-vlan.service.d/override.conf)


```bash
sudo systemctl daemon-reload
sudo systemctl enable --now lab-net1-vlan.service
systemctl status lab-net1-vlan.service --no-pager
```

---

## Step 3.4 - Configure the VLAN interfaces on the router

The LAN interface `enp5s0` now carries four 802.1Q VLANs, each with its own logical interface, gateway and `/26` subnet carved out of `10.114.22.0/24`.

| VLAN | Interface | Router IP | Subnet | Purpose |
|---|---|---|---|---|
| 10 | `enp5s0.10` | `10.114.22.1/26` | `10.114.22.0/26` | ADMIN |
| 20 | `enp5s0.20` | `10.114.22.65/26` | `10.114.22.64/26` | USERS |
| 30 | `enp5s0.30` | `10.114.22.129/26` | `10.114.22.128/26` | SERVERS |
| 40 | `enp5s0.40` | `10.114.22.193/26` | `10.114.22.192/26` | DMZ |

First, the parent interface declares the VLANs (this replaces the static `/24` file from Step 3.2):

```ini
# /etc/systemd/network/enp5s0.network
[Match]
Name=enp5s0

[Network]
VLAN=enp5s0.10
VLAN=enp5s0.20
VLAN=enp5s0.30
VLAN=enp5s0.40
```

Then one `.netdev` and one `.network` file per VLAN (example for VLAN 10; the others only change the name, the ID and the address):

```ini
# /etc/systemd/network/vlan10.netdev
[NetDev]
Name=enp5s0.10
Kind=vlan

[VLAN]
Id=10
```

```ini
# /etc/systemd/network/vlan10.network
[Match]
Name=enp5s0.10

[Network]
Address=10.114.22.1/26
```

The WAN interface asks for its address by DHCP:

```ini
# /etc/systemd/network/enp6s0.network
[Match]
Name=enp6s0

[Network]
DHCP=ipv4
```

```bash
systemctl enable --now systemd-networkd
systemctl restart systemd-networkd
```

**Result:** each VLAN has its own gateway on `router1`, and the WAN interface gets its address from `incusbr0`.

---

## Step 3.5 - Enable IPv4 forwarding

By default Linux drops packets that are not addressed to it. `ip_forward` tells the kernel to pass them from one interface to another, which is what makes it a router.

```ini
# /etc/sysctl.d/99-router.conf
net.ipv4.ip_forward=1
```

```bash
sysctl --system
```

---

## Step 3.6 - NAT with nftables

```bash
apt update
apt install nftables
```

Full ruleset: [`nftables.conf`](configs/nftables.conf)

- The `forward` chain lets routed traffic through.
- The `postrouting` rule masquerades packets from the lab subnet when they leave through `enp6s0`: the source address is replaced by the WAN interface's address, so private lab addresses can reach the outside.

```bash
nft -c -f /etc/nftables.conf
systemctl enable --now nftables
```

**Security note:** the forwarding policy is deliberately permissive so I can validate routing first. Restricting traffic between VLANs with explicit rules is the subject of Phase 4.

---

## Step 3.7 - Validation

Router state:

```bash
incus exec router1 -- ip -br addr
incus exec router1 -- ip route
incus exec router1 -- sysctl net.ipv4.ip_forward
incus exec router1 -- nft list ruleset
```

Client side (DHCP lease, IP connectivity, DNS):

```bash
incus exec client-iot -- ip -4 addr show eth0
incus exec client-users -- ping -c 3 10.114.22.65
incus exec client-users -- ping -c 3 1.1.1.1
incus exec client-users -- nslookup dns-server.homelab.local
```

![`Test DHCP and DNS`](assets/router1-enp5s0.png)

VLAN configuration on the host:

```bash
sudo bridge vlan show
ip -d link show lab-net1
```

![`VLAN configuration on the host`](assets/router1-enp5s0.png)

### Results

- Four separate IPv4 subnets, each with its own VLAN gateway on `router1`.
- `router1` connects the internal lab network to the upstream network.
- DHCP assigns addresses and network options to clients.
- Internal and external DNS resolution both work.
- Clients in the users and servers VLANs reach the Internet.
- NAT is done by `router1`; it is disabled on `lab-net1` to avoid a redundant translation.

**traceroute from a client :** 
![`traceroute from client-users`](assets/router1-enp5s0.png)

---

# Phase 4 - Firewall

**Goal:** control traffic, not just route it.

## Step 4.1 - nftables rules - practice
## Step 4.2 - Observing with Wireshark
## Step 4.3 - DROP vs REJECT
## Step 4.4 - pfSense - adopted firewall
## Step 4.5 - Equivalent rules in pfSense
## Step 4.6 - DROP vs REJECT in pfSense

---

# Phase 5 - Active Directory

**Goal:** understand the most common enterprise network environment.

## Step 5.1 - Domain controller
## Step 5.2 - Client machine
## Step 5.3 - GPO
## Step 5.4 - Low-privilege user

---

# Phase 6 - Cyber Blue Team (detection)

**Goal:** be able to detect attacks before launching them myself.

## Step 6.1 - Wazuh
## Step 6.2 - Sysmon
## Step 6.3 - Suricata
## Step 6.4 - Suricata on Raspberry Pi

---

# Phase 7 - Cyber Red Team (attack)

**Goal:** generate real attack traffic.

## Step 7.1 - Reconnaissance
## Step 7.2 - Cross-checking
## Step 7.3 - Exploitation and report

---

# Phase 8 - Virtual network segmentation

**Goal:** build a real enterprise-style architecture, with a final addressing scheme.

## Planned addressing scheme

`10.114.22.0/24` split into four `/26` subnets (64 addresses each):

```text
ADMIN   : 10.114.22.0/26    (10.114.22.1   - 10.114.22.62)
USERS   : 10.114.22.64/26   (10.114.22.65  - 10.114.22.126)
SERVERS : 10.114.22.128/26  (10.114.22.129 - 10.114.22.190)
DMZ     : 10.114.22.192/26  (10.114.22.193 - 10.114.22.254)
```

---

# Phase 9 - Moving to real hardware

**Hardware:** managed switch, router, Raspberry Pi.

## Step 9.1 - VLANs on the real switch
## Step 9.2 - Trunk (802.1Q)
## Step 9.3 - Router-on-a-stick
## Step 9.4 - ACLs on the real switch/router
## Step 9.5(optionnal) - Secure remote access (VPN)

---

# Phase 10 - HID injection

## Step 10.1 - Arduino: HID injection (BadUSB)

---

