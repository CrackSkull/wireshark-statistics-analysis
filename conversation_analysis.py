from scapy.all import rdpcap, IP
from collections import defaultdict

packets = rdpcap("exp7capture.pcang")

pair_data = defaultdict(lambda: {"bytes": 0, "count": 0, "times": []})

for pkt in packets:
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        pair = (src, dst)

        pair_data[pair]["bytes"] += len(pkt)
        pair_data[pair]["count"] += 1

        if hasattr(pkt, "time"):
            pair_data[pair]["times"].append(pkt.time)

# Find pair with max data
max_pair = None
max_bytes = 0

for pair in pair_data:
    if pair_data[pair]["bytes"] > max_bytes:
        max_bytes = pair_data[pair]["bytes"]
        max_pair = pair

print("\n--- Conversation Analysis ---")

print("\nPair with Maximum Data Transfer:")
print(f"{max_pair} -> {max_bytes} bytes")

print("\nDetails for each pair:\n")

for pair, data in pair_data.items():
    times = data["times"]
    avg_time = 0

    if len(times) > 1:
        diffs = [t2 - t1 for t1, t2 in zip(times[:-1], times[1:])]
        avg_time = sum(diffs) / len(diffs)

    print(f"Pair: {pair}")
    print(f"  Total Packets: {data['count']}")
    print(f"  Total Bytes: {data['bytes']}")
    print(f"  Avg Inter-Packet Time: {avg_time:.6f} sec\n")