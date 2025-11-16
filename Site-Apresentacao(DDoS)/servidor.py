# servidor.py (cole este arquivo no lugar do anterior)
from flask import Flask, jsonify, send_from_directory
import psutil, time, os, csv, threading
from threading import Lock

STATIC_DIR = "site"
PORT = 8080
CSV_FILE = "metrics.csv"

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="")

csv_lock = Lock()
metrics_lock = Lock()

# CSV init
if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "ts","cpu_percent","memory_percent","memory_used_mb","memory_total_mb",
            "tcp_established","bytes_sent","bytes_recv","network_usage_percent"
        ])

# state for network delta
prev_net = psutil.net_io_counters()
prev_ts = time.time()

# metric cache (filled by collector thread)
_metric_cache = {}
_metric_cache['timestamp'] = int(time.time())
_metric_cache['cpu_percent'] = 0.0
_metric_cache['memory_percent'] = 0.0
_metric_cache['memory_used_mb'] = 0.0
_metric_cache['memory_total_mb'] = 0.0
_metric_cache['tcp_established'] = 0
_metric_cache['bytes_sent_per_s'] = 0.0
_metric_cache['bytes_recv_per_s'] = 0.0
_metric_cache['network_usage_percent'] = 0.0

# try to auto-detect NIC speed (Linux)
def detect_nic_capacity_bytes_per_s(fallback=125_000_000):
    try:
        # choose a non-loopback interface with carrier up
        for ifname, addrs in psutil.net_if_addrs().items():
            if ifname == "lo": 
                continue
            stats = psutil.net_if_stats().get(ifname)
            if not stats or not stats.isup:
                continue
            # try read speed file on Linux
            path = f"/sys/class/net/{ifname}/speed"
            if os.path.exists(path):
                try:
                    sp = int(open(path).read().strip())
                    # sp in Mb/s
                    return int(sp * 125_000)  # Mb/s -> bytes/s: (sp * 1_000_000)/8 = sp*125_000
                except Exception:
                    pass
        return fallback
    except Exception:
        return fallback

NIC_CAPACITY = detect_nic_capacity_bytes_per_s()

def collector_loop():
    global prev_net, prev_ts, _metric_cache
    # initialize cpu_percent measurement: call once with interval=None
    psutil.cpu_percent(interval=None)
    while True:
        ts = int(time.time())
        # cpu: non-blocking, returns since last call
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()

        # conexões TCP
        try:
            conns = psutil.net_connections(kind='inet')
            tcp_est = sum(1 for c in conns if c.status == 'ESTABLISHED')
        except Exception:
            tcp_est = -1

        net = psutil.net_io_counters()
        now = time.time()
        delta = max(1e-6, now - prev_ts)
        bytes_sent_per_s = (net.bytes_sent - prev_net.bytes_sent) / delta
        bytes_recv_per_s = (net.bytes_recv - prev_net.bytes_recv) / delta
        total_bps = bytes_sent_per_s + bytes_recv_per_s
        usage_percent = min(100.0, (total_bps / NIC_CAPACITY) * 100.0)

        # update prev
        prev_net = net
        prev_ts = now

        # update cache atomically
        with metrics_lock:
            _metric_cache = {
                "timestamp": ts,
                "cpu_percent": round(cpu, 2),
                "memory_percent": round(mem.percent, 2),
                "memory_used_mb": round(mem.used/1024/1024, 2),
                "memory_total_mb": round(mem.total/1024/1024, 2),
                "tcp_established": tcp_est,
                "bytes_sent_per_s": round(bytes_sent_per_s, 1),
                "bytes_recv_per_s": round(bytes_recv_per_s, 1),
                "network_usage_percent": round(usage_percent, 1)
            }
        # append CSV safely
        try:
            with csv_lock:
                with open(CSV_FILE, "a", newline="") as f:
                    w = csv.writer(f)
                    w.writerow([
                        ts,
                        _metric_cache["cpu_percent"],
                        _metric_cache["memory_percent"],
                        _metric_cache["memory_used_mb"],
                        _metric_cache["memory_total_mb"],
                        _metric_cache["tcp_established"],
                        net.bytes_sent,
                        net.bytes_recv,
                        _metric_cache["network_usage_percent"]
                    ])
        except Exception:
            pass

        time.sleep(1)  # collect every 1 second

# start collector thread
t = threading.Thread(target=collector_loop, daemon=True)
t.start()

@app.route("/status")
def status():
    with metrics_lock:
        return jsonify(_metric_cache)

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
    print(f"Servidor em http://0.0.0.0:{PORT} (NIC_CAPACITY={NIC_CAPACITY} bytes/s)")
    app.run(host="0.0.0.0", port=PORT, threaded=True)
