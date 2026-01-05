import psycopg2
from scapy.all import rdpcap
from datetime import datetime

# ---- Database Connection ----
conn = psycopg2.connect(
    dbname="pcapdb",
    user="neha",
    password="neha123",
    host="localhost"
)
cur = conn.cursor()

# ---- Load PCAP File ----
pcap_file = "/mnt/tcp-analysis/capture.pcapng"   # update path if needed
packets = rdpcap(pcap_file)

print("Processing packets...")

for pkt in packets:
    if pkt.haslayer("IP"):
        src = pkt["IP"].src
        dst = pkt["IP"].dst
        proto = pkt["IP"].proto
        time = datetime.fromtimestamp(float(pkt.time))


        cur.execute(
            "INSERT INTO packets (src_ip, dst_ip, protocol, timestamp) VALUES (%s, %s, %s, %s)",
            (src, dst, str(proto), time)
        )

conn.commit()
cur.close()
conn.close()

print("Done! Data inserted into database.")

