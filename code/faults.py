"""Fault injection with exact ground truth, plus the three evaluation tasks.

Faults are injected into the ORIGINAL config text; the four transformation
methods are then applied to the faulty bundle. Ground truth is expressed in
terms of ORIGINAL identifiers, so a response produced under an obfuscating
method must be de-obfuscated before it can be scored -- which is what makes
this simultaneously a utility test and a return-path test.
"""
import ipaddress
import re

from generator import generate_configs
from pipeline import parse_config, build_graph

FAULT_TYPES = ("dangling_acl", "dangling_prefix_list", "p30_mismatch",
               "remote_as_mismatch", "clean")


def _devs(configs):
    return sorted(configs)


def inject(configs, fault, seed_idx=0):
    """Returns (new_configs, ground_truth_dict)."""
    cfg = dict(configs)
    devs = _devs(cfg)
    target = devs[seed_idx % len(devs)]

    if fault == "clean":
        return cfg, {"fault": "clean", "devices": [], "detail": "no fault"}

    if fault == "dangling_acl":
        m = parse_config(target, cfg[target])
        aclnum = sorted(m["acls"])[0]
        # delete the ACL definition, keep the interface access-group reference
        cfg[target] = "\n".join(
            ln for ln in cfg[target].splitlines()
            if not ln.startswith(f"access-list {aclnum} ")) + "\n"
        return cfg, {"fault": "dangling_acl", "devices": [target],
                     "detail": f"interface access-group references ACL {aclnum} "
                               f"which is not defined on {target}",
                     "acl": aclnum}

    if fault == "dangling_prefix_list":
        m = parse_config(target, cfg[target])
        pl = sorted(m["prefix_lists"])[0]
        cfg[target] = "\n".join(
            ln for ln in cfg[target].splitlines()
            if not ln.startswith(f"ip prefix-list {pl} ")) + "\n"
        return cfg, {"fault": "dangling_prefix_list", "devices": [target],
                     "detail": f"route-map matches prefix-list {pl} which is "
                               f"not defined on {target}",
                     "prefix_list": pl}

    if fault == "p30_mismatch":
        # find a /30 interface and move it into a different subnet
        for d in devs:
            m = parse_config(d, cfg[d])
            for i in m["interfaces"]:
                if i["mask"] == "255.255.255.252":
                    old = i["ip"]
                    net = ipaddress.ip_interface(f"{old}/30").network
                    newip = str(ipaddress.ip_address(
                        int(net.network_address) + 256 + 1))
                    cfg[d] = cfg[d].replace(
                        f" ip address {old} 255.255.255.252",
                        f" ip address {newip} 255.255.255.252")
                    return cfg, {"fault": "p30_mismatch", "devices": [d],
                                 "detail": f"interface {i['name']} on {d} was "
                                           f"moved from {old} to {newip}, so the "
                                           f"point-to-point link endpoints are no "
                                           f"longer in the same subnet",
                                 "interface": i["name"]}
        raise RuntimeError("no /30 found")

    if fault == "remote_as_mismatch":
        for d in devs:
            m = parse_config(d, cfg[d])
            if m["bgp"] and m["bgp"]["neighbors"]:
                peer = sorted(m["bgp"]["neighbors"])[0]
                ras = m["bgp"]["neighbors"][peer]["remote_as"]
                bad = str(int(ras) + 500)
                cfg[d] = cfg[d].replace(
                    f" neighbor {peer} remote-as {ras}",
                    f" neighbor {peer} remote-as {bad}")
                return cfg, {"fault": "remote_as_mismatch", "devices": [d],
                             "detail": f"BGP neighbor {peer} on {d} declares "
                                       f"remote-as {bad} but the peer's actual "
                                       f"local ASN is {ras}",
                             "peer": peer, "wrong_as": bad, "right_as": ras}
    raise ValueError(fault)


# ------------------------------------------------------------------- tasks
def task_ground_truth(task, configs, ground):
    """Ground truth in ORIGINAL identifier terms."""
    models = {d: parse_config(d, t) for d, t in configs.items()}

    if task == "T1_fault_detection":
        return {"fault": ground["fault"], "devices": ground["devices"],
                "detail": ground["detail"]}

    if task == "T2_reference_resolution":
        target = sorted(configs)[0]
        m = models[target]
        pairs = []
        for i in m["interfaces"]:
            if i["vrf"]:
                pairs.append((i["vrf"], i["acl_in"] or "none"))
        return {"device": target, "vrf_acl_pairs": sorted(pairs)}

    if task == "T3_topology":
        g = build_graph(list(models.values()))
        adj = set()
        for u, v, d in g.edges(data=True):
            if d.get("type") == "L3_ADJACENT_TO":
                du, dv = u.split(":IF:")[0], v.split(":IF:")[0]
                adj.add(tuple(sorted((du, dv))))
        return {"adjacent_pairs": sorted(adj)}

    raise ValueError(task)


TASKS = ("T1_fault_detection", "T2_reference_resolution", "T3_topology")


def build_prompt(task, bundle_text, name_map=None, target_device=None):
    """name_map maps ORIGINAL device id -> id as it appears in this bundle."""
    cfgs = "\n\n".join(f"===== device: {d} =====\n{t}"
                       for d, t in sorted(bundle_text.items()))
    devlist = ", ".join(sorted(bundle_text))
    if task == "T1_fault_detection":
        q = ("Examine the configuration bundle. Exactly one misconfiguration may "
             "be present, or the bundle may be correct.\n"
             "Answer in this format and nothing else:\n"
             "FAULT: <one of dangling_acl, dangling_prefix_list, p30_mismatch, "
             "remote_as_mismatch, none>\n"
             "DEVICE: <device name, or none>\n"
             "REASON: <one sentence>")
    elif task == "T2_reference_resolution":
        # The target must be the same physical device for every
        # transformation method. Selecting sorted(bundle_text)[0] would pick a
        # different device once names are obfuscated, so the caller passes the
        # device's name as it appears in this bundle.
        target = target_device if target_device in bundle_text \
            else sorted(bundle_text)[0]
        q = (f"For device {target} only, list every VRF-bound interface as a "
             f"pair of its VRF name and the ACL number applied inbound.\n"
             "Answer in this format and nothing else, one pair per line:\n"
             "PAIR: <vrf-name> <acl-number>")
    elif task == "T3_topology":
        q = ("Two interfaces are directly L3-adjacent when they are the only two "
             "interfaces in the same /30 subnet and sit on different devices. "
             f"Devices present: {devlist}.\n"
             "List every directly adjacent device pair.\n"
             "Answer in this format and nothing else, one pair per line:\n"
             "PAIR: <device-a> <device-b>")
    else:
        raise ValueError(task)
    # Reasoning-style models emit visible chain-of-thought and get
    # truncated before the answer tags, which measures format compliance
    # rather than analysis ability. State the constraint explicitly.
    return (f"You are analysing Cisco IOS configurations.\n\n{cfgs}\n\n{q}\n"
            "\nOutput ONLY the requested lines. Begin your reply with the "
            "first required line. Do not include reasoning, analysis, "
            "preamble, or explanation beyond the requested fields.\n")
