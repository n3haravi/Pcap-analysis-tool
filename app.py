from flask import Flask, render_template, request, redirect
import psycopg2
from scapy.all import rdpcap
import os

app = Flask(__name__)

# -------------------------
# Database connection
# -------------------------
def get_db_connection():
    return psycopg2.connect(
        dbname="pcapdb",
        user="neha",
        password="neha123",
        host="localhost"
    )

# -------------------------
# Upload page
# -------------------------
@app.route("/")
def index():
    return render_template("upload.html")

# -------------------------
# Upload + process PCAP
# -------------------------
@app.route("/upload", methods=["POST"])
def upload_file():
    file = request.files.get("pcapfile")

    if not file or file.filename == "":
        return "No file selected"

    # ensure uploads directory exists
    os.makedirs("uploads", exist_ok=True)

    filepath = os.path.join("uploads", file.filename)
    file.save(filepath)

    packets = rdpcap(filepath)
    rows_to_insert = []

    for pkt in packets:
        if pkt.haslayer("IP"):
            src_ip = pkt["IP"].src
            dst_ip = pkt["IP"].dst
            length = len(pkt)

            # -------- protocol decoding (VERY IMPORTANT) --------
            if pkt.haslayer("TCP"):
                protocol = "TCP"
                src_port = pkt["TCP"].sport
                dst_port = pkt["TCP"].dport
            elif pkt.haslayer("UDP"):
                protocol = "UDP"
                src_port = pkt["UDP"].sport
                dst_port = pkt["UDP"].dport
            else:
                protocol = "OTHER"
                src_port = None
                dst_port = None

            rows_to_insert.append(
                (src_ip, dst_ip, protocol, src_port, dst_port, length)
            )

    conn = get_db_connection()
    cur = conn.cursor()

    cur.executemany("""
        INSERT INTO packets
        (src_ip, dst_ip, protocol, src_port, dst_port, length)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, rows_to_insert)

    conn.commit()
    cur.close()
    conn.close()

    print(f"Inserted {len(rows_to_insert)} packets")

    # redirect to packet list (Wireshark-style)
    return redirect("/packets")

# -------------------------
# Packet list (Wireshark-style summary)
# -------------------------
@app.route("/packets")
def packets():
    q = request.args.get("q", "")
    proto = request.args.get("protocol", "")

    conn = get_db_connection()
    cur = conn.cursor()

    sql = """
        SELECT id, src_ip, dst_ip, protocol, length, timestamp
        FROM packets
        WHERE (%s = '' OR src_ip ILIKE %s OR dst_ip ILIKE %s)
          AND (%s = '' OR protocol = %s)
        ORDER BY id
        LIMIT 500
    """

    cur.execute(
        sql,
        (q, f"%{q}%", f"%{q}%", proto, proto)
    )

    rows = cur.fetchall()

    cur.close()
    conn.close()

    return render_template("packets.html", packets=rows)

# -------------------------
# Packet details (Wireshark middle pane)
# -------------------------
@app.route("/packet/<int:pid>")
def packet_detail(pid):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT src_ip, dst_ip, protocol,
               src_port, dst_port,
               length, timestamp
        FROM packets
        WHERE id = %s
    """, (pid,))

    packet = cur.fetchone()

    cur.close()
    conn.close()

    return render_template("packet_detail.html", packet=packet)

# -------------------------
# Run app
# -------------------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")

