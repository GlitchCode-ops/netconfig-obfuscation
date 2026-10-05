"""Tests for VRF-qualified subnet identity and the point-to-point adjacency
rule. Run: python3 test_graph_model.py"""
from pipeline import parse_config, build_graph, run_pipeline

a = "version 15.2\nhostname a-core-1\nip vrf CUST-X\ninterface GigabitEthernet0/1\n ip vrf forwarding CUST-X\n ip address 10.0.0.1 255.255.255.252\n!\nend\n"
b = "version 15.2\nhostname b-core-1\nip vrf CUST-Y\ninterface GigabitEthernet0/1\n ip vrf forwarding CUST-Y\n ip address 10.0.0.2 255.255.255.252\n!\nend\n"

def adj(G): return [(u,v) for u,v,d in G.edges(data=True) if d.get("type")=="L3_ADJACENT_TO"]
def subs(G): return [n for n in G.nodes if n.startswith("SUBNET:")]

G = build_graph([parse_config("A",a), parse_config("B",b)])
assert len(subs(G))==2 and not adj(G), "distinct VRFs must not collapse"

G = build_graph([parse_config("A",a), parse_config("B",b.replace("CUST-Y","CUST-X"))])
assert len(subs(G))==1 and len(adj(G))==1, "same VRF /30 must form adjacency"

c = "version 15.2\nhostname c-core-1\ninterface GigabitEthernet0/1\n ip address 192.0.2.0 255.255.255.254\n!\nend\n"
G = build_graph([parse_config("C",c), parse_config("D",c.replace("c-core-1","d-core-1").replace("192.0.2.0","192.0.2.1"))])
assert len(adj(G))==1, "/31 must form adjacency"

e = "version 15.2\nhostname e-core-1\ninterface GigabitEthernet0/1\n ip address 172.31.0.1 255.255.255.252\n!\ninterface GigabitEthernet0/2\n ip address 172.31.0.2 255.255.255.252\n!\nend\n"
G = build_graph([parse_config("E",e)])
assert not adj(G), "same-device pair must not form adjacency"
assert not any("confidence" in d for *_ ,d in G.edges(data=True)), "no confidence attr"

import ipaddress
models, obf, txt, g_o, g_b, ob = run_pipeline({"A":a,"B":b}, b"s", {"A":"nyc","B":"lon"})
ips=[i["ip"] for m in obf.values() for i in m["interfaces"]]
n1,n2=(ipaddress.ip_interface(ip+"/30").network for ip in ips)
assert n1!=n2, "different-VRF same-prefix must map independently"
from networkx.algorithms.isomorphism import GraphMatcher, categorical_node_match
assert GraphMatcher(g_o,g_b,node_match=categorical_node_match("type",None)).is_isomorphic()
print("ALL GRAPH-MODEL TESTS PASS")
