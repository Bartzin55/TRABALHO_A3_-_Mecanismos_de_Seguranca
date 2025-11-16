# servidor.py (ATUALIZADO)
from flask import Flask, jsonify, send_from_directory
import psutil, time, os, csv
from threading import Lock

STATIC_DIR = "site"
PORT = 8080
CSV_FILE = "metrics.csv"

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="")

csv_lock = Lock()

# Inicialização do CSV
if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "ts","cpu_percent","memory_percent","memory_used_mb","memory_total_mb",
            "tcp_established","bytes_sent","bytes_recv","network_usage_percent"
        ])

# Para cálculo de bytes/s
prev_net = psutil.net_io_counters()
prev_ts = time.time()

# Capacidade teórica da placa de rede (em bytes por segundo)
# 1 Gbps = 125 MB/s ≈ 125_000_000 bytes/s
NIC_CAPACITY = 125_000_000

def collect_metrics():
    global prev_net, prev_ts

    ts = int(time.time())
    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory()

    # conexões TCP
    try:
        conns = psutil.net_connections(kind='inet')
        tcp_est = sum(1 for c in conns if c.status == 'ESTABLISHED')
    except:
        tcp_est = -1

    # rede
    net = psutil.net_io_counters()
    now = time.time()
    delta = max(1e-6, now - prev_ts)

    bytes_sent_per_s = (net.bytes_sent - prev_net.bytes_sent) / delta
    bytes_recv_per_s = (net.bytes_recv - prev_net.bytes_recv) / delta

    total_bps = bytes_sent_per_s + bytes_recv_per_s
    usage_percent = min(100, (total_bps / NIC_CAPACITY) * 100)

    prev_net = net
    prev_ts = now

    metrics = {
        "timestamp": ts,
        "cpu_percent": round(cpu,2),
        "memory_percent": round(mem.percent,2),
        "memory_used_mb": round(mem.used/1024/1024,2),
        "memory_total_mb": round(mem.total/1024/1024,2),
        "tcp_established": tcp_est,
        "bytes_sent_per_s": round(bytes_sent_per_s,1),
        "bytes_recv_per_s": round(bytes_recv_per_s,1),
        "network_usage_percent": round(usage_percent,1)
    }

    # salva CSV
    try:
        with csv_lock:
            with open(CSV_FILE, "a", newline="") as f:
                w = csv.writer(f)
                w.writerow([
                    ts, cpu, mem.percent,
                    metrics["memory_used_mb"], metrics["memory_total_mb"],
                    tcp_est, net.bytes_sent, net.bytes_recv,
                    metrics["network_usage_percent"]
                ])
    except:
        pass

    return metrics

@app.route("/status")
def status():
    return jsonify(collect_metrics())

@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "monitoramento.html")

@app.route("/<path:pth>")
def proxy(pth):
    full = os.path.join(STATIC_DIR, pth)
    if os.path.exists(full) and os.path.isfile(full):
        return send_from_directory(STATIC_DIR, pth)
    return send_from_directory(STATIC_DIR, "monitoramento.html")

if __name__ == "__main__":
    print(f"Servidor em http://0.0.0.0:{PORT}")
    app.run(host="0.0.0.0", port=PORT, threaded=True)
