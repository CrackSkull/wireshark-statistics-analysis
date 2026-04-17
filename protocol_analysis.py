from scapy.all import rdpcap, IP

# Load your capture file (use your filename)
packets = rdpcap("exp7capture.pcang")

total_packets = len(packets)
total_size = 0
header_size = 0

for pkt in packets:
    # Total packet size
    total_size += len(pkt)

    # Header size (IP layer only)
    if IP in pkt:
        header_size += pkt[IP].ihl * 4

print("\n--- Protocol Analysis ---")
print("Total Packets:", total_packets)
print("Total Data Size:", total_size, "bytes")
print("Total Header Size:", header_size, "bytes")