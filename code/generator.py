"""Synthetic Cisco IOS configuration generator.

Generates multi-site, multi-device IOS-style configurations with realistic
cross-references (interfaces -> VRFs/ACLs, route-maps -> prefix-lists,
BGP neighbors -> peer interface addresses on shared /30 links) so that the
obfuscation pipeline can be evaluated on reference integrity, topology
preservation and cross-device consistency.

Deterministic given a seed.
"""

import ipaddress
import random

ROLES = ["core", "edge", "agg", "leaf"]
SITES = ["nyc", "lon", "fra", "sng", "sfo", "tok", "ams", "syd"]


class Device:
    def __init__(self, name, site, role, ordinal, asn):
        self.name = name
        self.site = site
        self.role = role
        self.ordinal = ordinal
        self.asn = asn
        self.interfaces = []      # list of dicts
        self.vrfs = []            # list of dicts
        self.acls_numbered = []   # (number, [lines])
        self.prefix_lists = []    # (name, [entries])
        self.route_maps = []      # (name, [clauses])
        self.bgp_neighbors = []   # (peer_ip, remote_as, rm_in, rm_out, vrf)
        self.ospf_networks = []   # (network, wildcard)
        self.secrets = []         # raw secret lines
        self.lan_subnets = []


def _p2p_link(pool):
    """Take the next /30 from the point-to-point pool."""
    return next(pool)


def generate_network(n_devices, seed=1234):
    rng = random.Random(seed)
    p2p_pool = ipaddress.ip_network("172.20.0.0/16").subnets(new_prefix=30)
    lan_pool = ipaddress.ip_network("10.96.0.0/12").subnets(new_prefix=24)
    loop_pool = ipaddress.ip_network("192.168.192.0/20").hosts()

    n_sites = max(1, n_devices // 4)
    devices = []
    for i in range(n_devices):
        site = SITES[(i // 4) % len(SITES)] + (str(i // (4 * len(SITES)) + 1)
                                               if i // 4 >= len(SITES) else "")
        role = ROLES[i % len(ROLES)]
        ordinal = i % 4 + 1
        asn = 65001 + (i // 4)  # one private ASN per site
        d = Device(f"{site}-{role}-{ordinal}", site, role, ordinal, asn)
        devices.append(d)

    # loopbacks
    for d in devices:
        ip = next(loop_pool)
        d.interfaces.append({"name": "Loopback0", "ip": str(ip), "mask": "255.255.255.255",
                             "desc": f"mgmt loopback {d.name}", "vrf": None, "acl_in": None})

    # VRFs + LAN interfaces + ACLs + prefix-lists + route-maps
    for idx, d in enumerate(devices):
        for v in range(2):
            vname = f"CUST-{d.site.upper()}-{v+1}"
            rd = f"{d.asn}:{100+v}"
            d.vrfs.append({"name": vname, "rd": rd,
                           "rt_export": rd, "rt_import": rd})
            lan = next(lan_pool)
            d.lan_subnets.append(lan)
            hosts = list(lan.hosts())
            aclnum = 100 + v
            d.acls_numbered.append((aclnum, [
                f"permit ip {lan.network_address} 0.0.0.255 any",
                f"deny   ip any any log",
            ]))
            d.interfaces.append({
                "name": f"GigabitEthernet0/{v+1}", "ip": str(hosts[0]),
                "mask": str(lan.netmask), "desc": f"{vname} LAN {d.site}",
                "vrf": vname, "acl_in": str(aclnum)})
            pl = f"PL-{vname}"
            d.prefix_lists.append((pl, [f"permit {lan.with_prefixlen}"]))
            rm = f"RM-{vname}-IN"
            d.route_maps.append((rm, [("permit", 10, f"match ip address prefix-list {pl}",
                                       "set local-preference 200")]))

    # point-to-point links: chain within site + one uplink between consecutive sites
    links = []  # (devA, devB, subnet)
    by_site = {}
    for d in devices:
        by_site.setdefault(d.site, []).append(d)
    for site, ds in by_site.items():
        for a, b in zip(ds, ds[1:]):
            links.append((a, b, _p2p_link(p2p_pool)))
    sites_sorted = list(by_site.values())
    for sa, sb in zip(sites_sorted, sites_sorted[1:]):
        links.append((sa[0], sb[0], _p2p_link(p2p_pool)))

    ifidx = {d.name: 0 for d in devices}
    for a, b, net in links:
        h = list(net.hosts())
        for dev, ip, peer, peer_ip in ((a, h[0], b, h[1]), (b, h[1], a, h[0])):
            ifidx[dev.name] += 1
            dev.interfaces.append({
                "name": f"TenGigabitEthernet1/{ifidx[dev.name]}",
                "ip": str(ip), "mask": str(net.netmask),
                "desc": f"to {peer.name}", "vrf": None, "acl_in": None})
            rm_in, rm_out = None, None
            if dev.route_maps:
                rm_in = dev.route_maps[0][0]
            dev.bgp_neighbors.append((str(peer_ip), peer.asn, rm_in, None, None))
            dev.ospf_networks.append((str(net.network_address), "0.0.0.3"))

    # secrets
    for d in devices:
        d.secrets = [
            f"enable secret 5 $1${rng.randbytes(4).hex()}$" + rng.randbytes(11).hex()[:22],
            f"username admin secret 5 $1${rng.randbytes(4).hex()}$" + rng.randbytes(11).hex()[:22],
            f"snmp-server community {d.site.upper()}snmp{rng.randint(100,999)} RO",
            f"crypto isakmp key {rng.randbytes(8).hex()} address {d.bgp_neighbors[0][0] if d.bgp_neighbors else '192.0.2.1'}",
        ]
    return devices, links


def render_ios(d: Device) -> str:
    out = ["version 15.2", f"hostname {d.name}", "!"]
    for s in d.secrets:
        out.append(s)
    out.append("!")
    for v in d.vrfs:
        out += [f"ip vrf {v['name']}", f" rd {v['rd']}",
                f" route-target export {v['rt_export']}",
                f" route-target import {v['rt_import']}", "!"]
    for i in d.interfaces:
        out.append(f"interface {i['name']}")
        if i["desc"]:
            out.append(f" description {i['desc']}")
        if i["vrf"]:
            out.append(f" ip vrf forwarding {i['vrf']}")
        out.append(f" ip address {i['ip']} {i['mask']}")
        if i["acl_in"]:
            out.append(f" ip access-group {i['acl_in']} in")
        out.append("!")
    for num, lines in d.acls_numbered:
        for ln in lines:
            out.append(f"access-list {num} {ln}")
    out.append("!")
    for name, entries in d.prefix_lists:
        for seq, e in enumerate(entries, start=5):
            out.append(f"ip prefix-list {name} seq {seq} {e}")
    out.append("!")
    for name, clauses in d.route_maps:
        for action, seq, match, setl in clauses:
            out.append(f"route-map {name} {action} {seq}")
            out.append(f" {match}")
            out.append(f" {setl}")
        out.append("!")
    out.append(f"router ospf 100")
    out.append(f" router-id {d.interfaces[0]['ip']}")
    for net, wc in d.ospf_networks:
        out.append(f" network {net} {wc} area 0")
    out.append("!")
    out.append(f"router bgp {d.asn}")
    out.append(f" bgp router-id {d.interfaces[0]['ip']}")
    for ip, ras, rmi, rmo, vrf in d.bgp_neighbors:
        out.append(f" neighbor {ip} remote-as {ras}")
        if rmi:
            out.append(f" neighbor {ip} route-map {rmi} in")
        if rmo:
            out.append(f" neighbor {ip} route-map {rmo} out")
    out.append("!")
    out.append("end")
    return "\n".join(out) + "\n"


def generate_configs(n_devices, seed=1234):
    devices, links = generate_network(n_devices, seed)
    return {d.name: render_ios(d) for d in devices}, devices, links


if __name__ == "__main__":
    cfgs, devs, links = generate_configs(8)
    print(next(iter(cfgs.values())))
    print(f"{len(devs)} devices, {len(links)} links")
