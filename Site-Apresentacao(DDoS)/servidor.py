# servidor.py (sampler em background)
from flask import Flask, jsonify, send_from_directory
import psutil, time, os, csv
from threading import Lock, Thread

STATIC_DIR = "site"
PORT = 8080
CSV_FILE = "metrics.csv"

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="")

metrics_lock = Lock()
# inicializa um dicionário com valores razoáveis
metrics = {
    "timestamp": int(time.time()),
    "cpu_percent": 0.0,
    "memory_percent": 0.0,
    "memory_used_mb": 0.0,
    "memory_total_mb": 0.0,
    "tcp_established": -1,
    "bytes_sent_per_s": 0.0,
    "bytes_recv_per_s": 0.0,
    "network_usage_percent": 0.0
}

# CSV header init
if not os.path.exists(CSV_FILE):
    try:
        with open(CSV_FILE, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow([
                "ts","cpu_percent","memory_percent","memory_used_mb","memory_total_mb",
                "tcp_established","bytes_sent","bytes_recv","network_usage_percent"
            ])
    except Exception as e:
        print("Warning: não foi possível criar CSV:", e)

# NIC capacity default (bytes/s) -> 1 Gbps
NIC_CAPACITY = 125_000_000

# estado para cálculo de bytes/s
_prev_net = psutil.net_io_counters()
_prev_ts = time.time()

def sampler_loop():
    global _prev_net, _prev_ts, metrics

    tcp_sample_counter = 0
    while True:
        now = time.time()

        # CPU: usar interval=None aqui porque chamamos periodicamente
        cpu = psutil.cpu_percent(interval=None)

        # memória
        mem = psutil.virtual_memory()

        # conexões TCP (executar a cada 5 amostras para evitar custo alto)
        tcp_est = -1
        if tcp_sample_counter % 5 == 0:
            try:
                conns = psutil.net_connections(kind='inet')
                tcp_est = sum(1 for c in conns if c.status == 'ESTABLISHED')
            except Exception:
                tcp_est = -1
        tcp_sample_counter += 1

        # rede: calcular bytes/s
        net = psutil.net_io_counters()
        delta = max(1e-6, now - _prev_ts)
        bytes_sent_per_s = (net.bytes_sent - _prev_net.bytes_sent) / delta
        bytes_recv_per_s = (net.bytes_recv - _prev_net.bytes_recv) / delta
        total_bps = bytes_sent_per_s + bytes_recv_per_s

        # calcula uso percentual de NIC (cap em bytes/s)
        try:
            usage_percent = min(100.0, (total_bps / NIC_CAPACITY) * 100.0)
        except Exception:
            usage_percent = 0.0

        # atualiza prev
        _prev_net = net
        _prev_ts = now

        # atualiza metrics com lock
        with metrics_lock:
            metrics["timestamp"] = int(now)
            metrics["cpu_percent"] = round(cpu, 2)
            metrics["memory_percent"] = round(mem.percent, 2)
            metrics["memory_used_mb"] = round(mem.used / 1024 / 1024, 2)
            metrics["memory_total_mb"] = round(mem.total / 1024 / 1024, 2)
            # só atualiza tcp_est quando foi medido; se não medido, mantém o antigo
            if tcp_est >= 0:
                metrics["tcp_established"] = tcp_est
            metrics["bytes_sent_per_s"] = round(bytes_sent_per_s, 1)
            metrics["bytes_recv_per_s"] = round(bytes_recv_per_s, 1)
            metrics["network_usage_percent"] = round(usage_percent, 1)

        # append CSV em background (tente não falhar)
        try:
            with open(CSV_FILE, "a", newline="") as f:
                w = csv.writer(f)
                w.writerow([
                    int(now),
                    metrics["cpu_percent"],
                    metrics["memory_percent"],
                    metrics["memory_used_mb"],
                    metrics["memory_total_mb"],
                    metrics["tcp_established"],
                    net.bytes_sent,
                    net.bytes_recv,
                    metrics["network_usage_percent"]
                ])
        except Exception:
            pass

        # dormir ~1s (ajusta para 1s de amostragem)
        time.sleep(1.0)

# inicia o sampler em thread daemon
t = Thread(target=sampler_loop, daemon=True)
t.start()

@app.route("/status")
def status():
    # retorna cópia das métricas atuais
    with metrics_lock:
        snapshot = dict(metrics)
    return jsonify(snapshot)

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
