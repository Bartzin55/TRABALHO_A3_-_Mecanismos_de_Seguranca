# servidor.py (corrigido: coletor em background)
from flask import Flask, jsonify, send_from_directory
import psutil, time, os, csv
from threading import Lock, Thread

STATIC_DIR = "site"
PORT = 8090
CSV_FILE = "metrics.csv"

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="")

csv_lock = Lock()
metrics_lock = Lock()

# último snapshot guardado (inicial)
_latest_metrics = {
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

# CSV init (se não existe)
if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "ts","cpu_percent","memory_percent","memory_used_mb","memory_total_mb",
            "tcp_established","bytes_sent","bytes_recv","network_usage_percent"
        ])

# variáveis para cálculo de bytes/s
_prev_net = psutil.net_io_counters()
_prev_ts = time.time()

def detectar_capacidade_nic():
    """Tenta detectar velocidade da interface principal via psutil; fallback 1Gbps."""
    try:
        stats = psutil.net_if_stats()
        # pega a primeira interface que esteja UP e com speed conhecido
        for name, st in stats.items():
            if st.isup and st.speed and st.speed > 0:
                # st.speed está em Mbps — converte para bytes/s (1 Mbps = 125000 bytes/s)
                return int(st.speed * 125_000)
    except Exception:
        pass
    # fallback 1 Gbps
    return 125_000_000

NIC_CAPACITY = detectar_capacidade_nic()

def collect_once():
    """Coleta as métricas uma vez e atualiza _latest_metrics (thread-safe)."""
    global _prev_net, _prev_ts, NIC_CAPACITY

    ts = int(time.time())
    # usamos cpu_percent(interval=None) para que a média seja entre chamadas
    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory()

    # conexões TCP (pode ser custoso em alguns SOs; já está em thread)
    try:
        conns = psutil.net_connections(kind='inet')
        tcp_est = sum(1 for c in conns if c.status == 'ESTABLISHED')
    except Exception:
        tcp_est = -1

    net = psutil.net_io_counters()
    now = time.time()
    delta = max(1e-6, now - _prev_ts)

    bytes_sent_per_s = (net.bytes_sent - _prev_net.bytes_sent) / delta
    bytes_recv_per_s = (net.bytes_recv - _prev_net.bytes_recv) / delta

    total_bps = bytes_sent_per_s + bytes_recv_per_s
    usage_percent = min(100.0, (total_bps / NIC_CAPACITY) * 100.0)

    _prev_net = net
    _prev_ts = now

    metrics = {
        "timestamp": ts,
        "cpu_percent": round(cpu, 2),
        "memory_percent": round(mem.percent, 2),
        "memory_used_mb": round(mem.used / 1024 / 1024, 2),
        "memory_total_mb": round(mem.total / 1024 / 1024, 2),
        "tcp_established": tcp_est,
        "bytes_sent_per_s": round(bytes_sent_per_s, 1),
        "bytes_recv_per_s": round(bytes_recv_per_s, 1),
        "network_usage_percent": round(usage_percent, 1)
    }

    # grava CSV (append) de forma protegida
    try:
        with csv_lock:
            with open(CSV_FILE, "a", newline="") as f:
                w = csv.writer(f)
                w.writerow([
                    ts,
                    metrics["cpu_percent"],
                    metrics["memory_percent"],
                    metrics["memory_used_mb"],
                    metrics["memory_total_mb"],
                    tcp_est,
                    net.bytes_sent,
                    net.bytes_recv,
                    metrics["network_usage_percent"]
                ])
    except Exception as e:
        # não interromper: só loga
        print("Warning: falha ao escrever CSV:", e)

    # atualiza snapshot global
    with metrics_lock:
        _latest_metrics.update(metrics)

def collector_loop(interval=1.0):
    """Loop que roda em background coletando a cada `interval` segundos."""
    # primeira chamada para inicializar o delta do cpu_percent / net counters
    psutil.cpu_percent(interval=None)
    global _prev_net, _prev_ts
    _prev_net = psutil.net_io_counters()
    _prev_ts = time.time()

    while True:
        try:
            collect_once()
        except Exception as e:
            print("Collector warning:", e)
        time.sleep(interval)

# rota que retorna o último snapshot (rápido)
@app.route("/status")
def status():
    with metrics_lock:
        return jsonify(dict(_latest_metrics))

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
    # iniciar thread coletora
    t = Thread(target=collector_loop, args=(1.0,), daemon=True)
    t.start()
    print(f"Servidor em http://0.0.0.0:{PORT} (NIC cap ~ {NIC_CAPACITY} bytes/s)")
    app.run(host="0.0.0.0", port=PORT, threaded=True)