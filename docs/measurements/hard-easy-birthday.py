#!/usr/bin/env python3
"""Does the hard/easy birthday technique actually work against our NATs?

Topology, built once and reused across trials with fresh source ports so no
conntrack entry is ever reused (the mistake that made the port-prediction
experiment report all three NAT flavours as cones):

    A (private) -- NAT_A: masquerade fully-random  --\\
                                                      >-- public bridge
    B (private) -- NAT_B: masquerade (cone)        --/

A is the "hard" side: a fresh external port per destination, unpredictable.
B is the "easy" side: one external port reused, so its address is knowable.

The technique:
  * A opens N sockets and sends one datagram from each to B's known external
    ip:port. Each socket earns a distinct external port on A's NAT. A does not
    need these to arrive — they exist to create the mappings.
  * B sends M probes from ONE socket to A's external IP at random ports. B's
    cone NAT keeps one external port for all of them, which is exactly the
    source A's NAT is expecting, so the filter is satisfied and only the port
    has to be hit.
  * Success = one of A's sockets receives something.

Usage: birthday.py [trials] [N] [M]
"""
import random
import socket
import subprocess
import sys
import time

NS_A, NS_B, NS_NA, NS_NB, NS_PUB = "bd-a", "bd-b", "bd-na", "bd-nb", "bd-pub"
PUB = "10.95.0.10"
A_OUT, B_OUT = "10.95.0.2", "10.95.0.3"
A_IN_GW, A_IN = "10.95.1.1", "10.95.1.2"
B_IN_GW, B_IN = "10.95.2.1", "10.95.2.2"
REFLECT_PORT = 3478


def run(*args, check=True):
    return subprocess.run(args, capture_output=True, text=True, check=check)


def ns(name, *args, check=True):
    return run("ip", "netns", "exec", name, *args, check=check)


def teardown():
    for n in (NS_A, NS_B, NS_NA, NS_NB, NS_PUB):
        subprocess.run(["ip", "netns", "del", n], capture_output=True)


def veth(dev_a, ns_a, ip_a, dev_b, ns_b, ip_b):
    run("ip", "link", "add", dev_a, "netns", ns_a, "type", "veth",
        "peer", "name", dev_b, "netns", ns_b)
    for dev, n, ip in ((dev_a, ns_a, ip_a), (dev_b, ns_b, ip_b)):
        if ip:
            ns(n, "ip", "addr", "add", f"{ip}/24", "dev", dev)
        ns(n, "ip", "link", "set", dev, "up")


def nat(tag, nat_ns, outer, inner, host_ns, host, symmetric):
    veth(f"{tag}o", nat_ns, outer, f"{tag}op", NS_PUB, None)
    ns(NS_PUB, "ip", "link", "set", f"{tag}op", "master", "bd-br")
    ns(nat_ns, "ip", "route", "add", "default", "via", PUB)
    veth(f"{tag}i", nat_ns, inner, f"{tag}n", host_ns, host)
    ns(host_ns, "ip", "route", "add", "default", "via", inner)
    ns(nat_ns, "sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward")
    ns(nat_ns, "nft", "add", "table", "ip", "t")
    ns(nat_ns, "nft", "add", "chain", "ip", "t", "post",
       "{ type nat hook postrouting priority 100 ; }")
    rule = f"oifname {tag}o masquerade" + (" fully-random" if symmetric else "")
    ns(nat_ns, "sh", "-c", f"nft add rule ip t post {rule}")
    # A real NAT drops unsolicited inbound rather than answering it; without
    # this the namespace itself replies ICMP and confirms a conntrack entry
    # that steals the reply tuple (finding 23).
    ns(nat_ns, "nft", "add", "chain", "ip", "t", "fwdf",
       "{ type filter hook forward priority 0 ; }")
    ns(nat_ns, "sh", "-c",
       f"nft add rule ip t fwdf iifname {tag}o ct state established,related accept")
    ns(nat_ns, "sh", "-c", f"nft add rule ip t fwdf iifname {tag}o drop")
    # And the same on the INPUT hook, which is finding 23 one hop over and cost
    # this experiment an hour. A probe addressed to the NAT's own outer address
    # is delivered to the NAT namespace, which has no listener, so the kernel
    # answers ICMP unreachable and CONFIRMS a conntrack entry for it. That entry
    # occupies the reply tuple (peer:R -> outer:P), so when the inside host
    # later needs a mapping toward peer:R it cannot keep port P and masquerade
    # allocates a fresh one -- and a cone starts behaving like a symmetric NAT.
    # A DROP at filter priority 0 runs before the confirm hook, so the entry is
    # never confirmed and the tuple stays free.
    ns(nat_ns, "nft", "add", "chain", "ip", "t", "inp",
       "{ type filter hook input priority 0 ; }")
    ns(nat_ns, "sh", "-c",
       f"nft add rule ip t inp iifname {tag}o ct state established,related accept")
    ns(nat_ns, "sh", "-c", f"nft add rule ip t inp iifname {tag}o drop")


def build():
    teardown()
    for n in (NS_A, NS_B, NS_NA, NS_NB, NS_PUB):
        run("ip", "netns", "add", n)
        ns(n, "ip", "link", "set", "lo", "up")
    ns(NS_PUB, "ip", "link", "add", "bd-br", "type", "bridge")
    ns(NS_PUB, "ip", "link", "set", "bd-br", "up")
    ns(NS_PUB, "ip", "addr", "add", f"{PUB}/24", "dev", "bd-br")
    nat("a", NS_NA, A_OUT, A_IN_GW, NS_A, A_IN, symmetric=True)
    nat("b", NS_NB, B_OUT, B_IN_GW, NS_B, B_IN, symmetric=False)


REFLECTOR = f"""
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("{PUB}", {REFLECT_PORT}))
while True:
    d, a = s.recvfrom(64)
    s.sendto(("%s:%d" % a).encode(), a)
"""

# B: learn my own external ip:port from the reflector, print it, then blast M
# probes at A's external IP on random ports -- all from the SAME socket, so the
# cone NAT keeps one external port and A's filter is satisfied.
B_SIDE = """
import socket, random, sys, time
port = int(sys.argv[1]); m = int(sys.argv[2]); seed = int(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("{b_in}", port)); s.settimeout(2)
s.sendto(b"?", ("{pub}", {refl}))
try:
    mapped = s.recv(64).decode()
except socket.timeout:
    print("NOMAP"); sys.exit(0)
print("MAPPED " + mapped, flush=True)
sys.stdin.readline()                      # wait until A has opened its sockets
rng = random.Random(seed)
targets = rng.sample(range(1024, 65535), m)
start = time.time()
for p in targets:
    s.sendto(b"knock", ("{a_out}", p))
print("SENT %d in %.3fs" % (m, time.time() - start), flush=True)
time.sleep(3)
""".format(b_in=B_IN, pub=PUB, refl=REFLECT_PORT, a_out=A_OUT)

# A: open N sockets, one datagram each toward B's known external ip:port, then
# wait to see whether any of them is knocked on.
A_SIDE = """
import socket, sys, select, time
dest_ip, dest_port, n = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
socks = []
for i in range(n):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("{a_in}", 0)); s.setblocking(False)
    s.sendto(b"open", (dest_ip, dest_port))
    socks.append(s)
print("OPENED %d" % len(socks), flush=True)
sys.stdin.readline()                      # B has now blasted
start = time.time()
hits = 0
while time.time() - start < 4.0:
    r, _, _ = select.select(socks, [], [], 0.25)
    for s in r:
        try:
            s.recvfrom(64); hits += 1
        except BlockingIOError:
            pass
    if hits:
        break
print("HITS %d after %.3fs" % (hits, time.time() - start), flush=True)
""".format(a_in=A_IN)


def trial(seed, n, m):
    """One attempt. Returns (hit, seconds_for_the_blast)."""
    b = subprocess.Popen(
        ["ip", "netns", "exec", NS_B, "python3", "-c", B_SIDE,
         str(40000 + seed), str(m), str(seed)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    line = b.stdout.readline().strip()
    if not line.startswith("MAPPED"):
        b.kill()
        return None, 0.0
    mapped = line.split(" ", 1)[1]
    ip, port = mapped.rsplit(":", 1)

    a = subprocess.Popen(
        ["ip", "netns", "exec", NS_A, "python3", "-c", A_SIDE, ip, port, str(n)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    opened = a.stdout.readline().strip()
    assert opened.startswith("OPENED"), opened

    b.stdin.write("go\n"); b.stdin.flush()          # blast
    sent = b.stdout.readline().strip()
    blast = float(sent.split(" in ")[1].rstrip("s")) if " in " in sent else 0.0
    a.stdin.write("go\n"); a.stdin.flush()          # now look for a knock
    result = a.stdout.readline().strip()
    hits = int(result.split()[1])
    for p in (a, b):
        p.kill()
        p.wait()
    return hits > 0, blast


def main():
    trials = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 256
    m = int(sys.argv[3]) if len(sys.argv) > 3 else 256
    build()
    refl = subprocess.Popen(["ip", "netns", "exec", NS_PUB, "python3", "-c", REFLECTOR])
    time.sleep(1)
    try:
        wins = 0
        blasts = []
        for i in range(trials):
            hit, blast = trial(i + 1, n, m)
            if hit is None:
                print(f"  trial {i+1}: no reflection (skipped)")
                continue
            wins += bool(hit)
            blasts.append(blast)
            print(f"  trial {i+1}: {'HIT ' if hit else 'miss'}  blast={blast:.3f}s")
        done = len(blasts)
        print()
        print(f"N={n} sockets on the hard side, M={m} probes from the easy side")
        print(f"success: {wins}/{done} = {100.0*wins/max(done,1):.0f}%")
        if blasts:
            print(f"blast time: median {sorted(blasts)[len(blasts)//2]:.3f}s")
        k = 64511
        pred = 1.0 - (1.0 - n / k) ** m
        print(f"predicted by the birthday arithmetic over ~{k} ports: {100*pred:.0f}%")
    finally:
        refl.kill()
        teardown()


if __name__ == "__main__":
    main()
