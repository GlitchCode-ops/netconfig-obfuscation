"""Regression tests for the obfuscation pipeline.

Covers VRF-qualified subnet identity, protected numeric-field detection,
BGP peer prefix derivation, wildcard-derived ACL prefix lengths, disjoint
numbered-ACL allocation and residual-value-scanner scaling.

Each test is written to be independent of the synthetic generator so that it
exercises the intended mechanism, not a shape the generator happens
to produce.
"""
import ipaddress
import re
import sys
import time

from pipeline import parse_config, build_graph, run_pipeline, Obfuscator

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  -- {detail}" if detail else ""))
    return ok


# ---------------------------------------------------------------
def test_vrf_context_same_site():
    """Eq.(1) claims context(v) (the VRF) is part of subnet identity, so the
    same prefix in two VRFs must map independently. Both devices are in the
    SAME site, so scope cannot be doing the separating."""
    a = ("version 15.2\nhostname aa-core-1\nip vrf CUST-X\ninterface GigabitEthernet0/1\n"
         " ip vrf forwarding CUST-X\n ip address 10.50.0.1 255.255.255.0\n!\nend\n")
    b = ("version 15.2\nhostname aa-core-2\nip vrf CUST-Y\ninterface GigabitEthernet0/1\n"
         " ip vrf forwarding CUST-Y\n ip address 10.50.0.1 255.255.255.0\n!\nend\n")
    # NOTE: identical site "site1" for both -> same scope key
    models, obf, txt, g_o, g_b, ob = run_pipeline(
        {"A": a, "B": b}, b"secret-fix1", {"A": "site1", "B": "site1"})
    ips = []
    for m in obf.values():
        for i in m["interfaces"]:
            if i["ip"]:
                ips.append(i["ip"])
    nets = {str(ipaddress.ip_interface(f"{ip}/24").network) for ip in ips}
    return check("VRF-qualified subnet identity: cross-VRF prefixes map independently",
                 len(nets) == 2, f"got {len(nets)} distinct synthetic subnet(s): {sorted(nets)}")


# ---------------------------------------------------------------
def test_security_scanner_covers_asn_aclnum_rdrt():
    """v_security must flag original ASNs, numbered-ACL ids and RD/RT values.
    We build a fake 'obfuscated' text that deliberately retains them."""
    import validate
    cfg = ("version 15.2\nhostname zz-core-1\nip vrf CUST-Z\n rd 65123:100\n"
           " route-target export 65123:100\n route-target import 65123:100\n!\n"
           "interface GigabitEthernet0/1\n ip vrf forwarding CUST-Z\n"
           " ip address 10.77.0.1 255.255.255.0\n ip access-group 142 in\n!\n"
           "access-list 142 permit ip any any\n!\n"
           "router bgp 65123\n neighbor 10.77.0.2 remote-as 65124\n!\nend\n")
    models = {"D": parse_config("D", cfg)}
    # leaked output: ASN, ACL number and RD all retained verbatim
    leaked = ("hostname HN_AAAAAA\nip vrf VRF_BBBBBB\n rd 65123:100\n"
              "interface GigabitEthernet0/1\n ip address 192.168.5.1 255.255.255.0\n"
              " ip access-group 142 in\n"
              "access-list 142 permit ip any any\n"
              "router bgp 65123\n neighbor 192.168.5.2 remote-as 65124\n")
    leaked_models = {"D": parse_config("D", leaked)}
    errs = validate.v_security(models, {"D": leaked}, report_numeric=True)
    blob = " ".join(errs)
    found_asn = "65123" in blob or "65124" in blob
    found_acl = "142" in blob
    found_rd = "65123:100" in blob
    ok = found_asn and found_acl and found_rd
    return check("security scanner flags ASN, ACL number and RD/RT leaks",
                 ok, f"asn={found_asn} aclnum={found_acl} rd={found_rd} errs={len(errs)}")


# ---------------------------------------------------------------
def test_bgp_peer_prefixlen_derived():
    """A BGP neighbour inside a /24 LAN must land in the SAME synthetic subnet
    as the local interface. Hardcoding /30 breaks this."""
    cfg = ("version 15.2\nhostname bb-core-1\ninterface GigabitEthernet0/1\n"
           " ip address 10.60.0.1 255.255.255.0\n!\n"
           "router bgp 65200\n neighbor 10.60.0.9 remote-as 65201\n!\nend\n")
    models, obf, txt, g_o, g_b, ob = run_pipeline(
        {"D": cfg}, b"secret-fix4a", {"D": "s1"})
    m = list(obf.values())[0]
    if_ip = m["interfaces"][0]["ip"]
    peer_ip = list(m["bgp"]["neighbors"].keys())[0]
    n1 = ipaddress.ip_interface(f"{if_ip}/24").network
    n2 = ipaddress.ip_interface(f"{peer_ip}/24").network
    same = (n1 == n2)
    off_ok = (int(ipaddress.ip_address(peer_ip)) - int(n2.network_address)) == 9
    return check("BGP peer prefix length derived from local subnet",
                 same and off_ok, f"if={if_ip} peer={peer_ip} same_net={same} offset9={off_ok}")


# ---------------------------------------------------------------
def test_ace_prefixlen_from_wildcard():
    """An ACE with wildcard 0.0.255.255 is a /16, not a /24. Hardcoding /24
    mis-groups the address and can collide distinct networks."""
    cfg = ("version 15.2\nhostname cc-core-1\ninterface GigabitEthernet0/1\n"
           " ip address 10.61.0.1 255.255.255.0\n ip access-group 150 in\n!\n"
           "access-list 150 permit ip 172.30.0.0 0.0.255.255 any\n"
           "access-list 150 permit ip 172.30.1.0 0.0.0.255 any\n!\nend\n")
    models, obf, txt, g_o, g_b, ob = run_pipeline(
        {"D": cfg}, b"secret-fix4b", {"D": "s1"})
    m = list(obf.values())[0]
    bodies = [a["body"] for a in m["acls"]["150"]] if "150" in m["acls"] else \
             [a["body"] for k in m["acls"] for a in m["acls"][k]]
    txt_all = " ".join(bodies)
    ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", txt_all)
    ips = [i for i in ips if not i.startswith("0.")]
    # the /16 entry must map to a .0.0 network base under a /16 mapping
    ok = False
    if len(ips) >= 2:
        a16 = ipaddress.ip_address(ips[0])
        # a /16-mapped base has zero in the last two octets
        ok = (int(a16) & 0xFFFF) == 0
    return check("ACE granularity derived from wildcard mask",
                 ok, f"aces={ips[:2]} (first should be a /16 base, x.y.0.0)")


# ---------------------------------------------------------------
def test_aclnum_not_equal_original():
    """Synthetic ACL numbers must not collide with ANY original ACL number in
    the bundle (the stated disjointness invariant)."""
    cfg_a = ("version 15.2\nhostname dd-core-1\ninterface GigabitEthernet0/1\n"
             " ip address 10.62.0.1 255.255.255.0\n ip access-group 100 in\n!\n"
             "access-list 100 permit ip any any\n!\nend\n")
    cfg_b = ("version 15.2\nhostname dd-core-2\ninterface GigabitEthernet0/1\n"
             " ip address 10.62.1.1 255.255.255.0\n ip access-group 101 in\n!\n"
             "access-list 101 permit ip any any\n!\nend\n")
    # scale matters: collisions only become likely once many scopes each remap
    # within the same numeric class, so use the 200-device bundle.
    from generator import generate_configs
    configs, devices, links = generate_configs(200, 1234)
    site_of = {d.name: d.site for d in devices}
    models, obf, txt, g_o, g_b, ob = run_pipeline(
        configs, b"session-secret-0001", site_of)
    originals = {str(k) for m in models.values() for k in m["acls"]}
    synth = set()
    for m in obf.values():
        synth.update(m["acls"].keys())
    overlap = originals & synth
    return check("synthetic ACL ids disjoint from all original ids",
                 not overlap, f"synthetic={sorted(synth)} overlap={sorted(overlap)}")


# ---------------------------------------------------------------
def test_security_scanner_is_linear():
    """Scanner must not be O(values x corpus). Compare 25 vs 100 devices:
    linear-ish growth (<8x for 4x input) rather than quadratic (~16x)."""
    import validate
    from generator import generate_configs
    times = {}
    for n in (25, 100):
        configs, devices, links = generate_configs(n, 1234)
        site_of = {d.name: d.site for d in devices}
        models, obf, txt, g_o, g_b, ob = run_pipeline(configs, b"perf", site_of)
        t0 = time.perf_counter()
        validate.v_security(models, txt)
        times[n] = time.perf_counter() - t0
    ratio = times[100] / max(times[25], 1e-9)
    return check("security scanner scales sub-quadratically",
                 ratio < 8.0, f"t25={times[25]*1000:.0f}ms t100={times[100]*1000:.0f}ms ratio={ratio:.1f}x (quadratic~16x)")


if __name__ == "__main__":
    print("=" * 70)
    for fn in (test_vrf_context_same_site,
               test_security_scanner_covers_asn_aclnum_rdrt,
               test_bgp_peer_prefixlen_derived,
               test_ace_prefixlen_from_wildcard,
               test_aclnum_not_equal_original,
               test_security_scanner_is_linear):
        try:
            fn()
        except Exception as e:
            check(fn.__name__, False, f"EXCEPTION {type(e).__name__}: {e}")
    print("=" * 70)
    n_pass = sum(1 for _, ok, _ in RESULTS if ok)
    print(f"{n_pass}/{len(RESULTS)} passing")
    sys.exit(0 if n_pass == len(RESULTS) else 1)
