# servidor.py
from flask import Flask, jsonify, send_from_directory
import psutil, time, os, csv
from threading import Lock

# Ajuste: a pasta que contém seus HTML/CSS é "site"
STATIC_DIR = "site"
PORT = 8080
CSV_FILE = "metrics.csv"

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="")

# Garantir lock ao escrever CSV
csv_lock = Lock()

# Inicialização do CSV (cabeçalho)
if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ts","cpu_percent","memory_percent","memory_used_mb","memory_total_mb",
                    "tcp_established","bytes_sent","bytes_recv"])

# estado para calcular bytes/s
prev_net = psutil.net_io_counters()
prev_ts = time.time()

def collect_metrics():
    global prev_net, prev_ts
    ts = int(time.time())
    # cpu com pequeno intervalo para valor mais confiável
    cpu = psutil.cpu_percent(interval=0.05)
    mem = psutil.virtual_memory()

    # contar conexões TCP ESTABLISHED (pode requerer permissões em alguns SO)
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
        "bytes_recv_per_s": round(bytes_recv_per_s,1)
    }

    # grava CSV (append)
    try:
        with csv_lock:
            with open(CSV_FILE, "a", newline="") as f:
                w = csv.writer(f)
                w.writerow([ts, metrics["cpu_percent"], metrics["memory_percent"],
                            metrics["memory_used_mb"], metrics["memory_total_mb"],
                            metrics["tcp_established"], net.bytes_sent, net.bytes_recv])
    except Exception as e:
        # não quebrar a rota se escrever falhar
        print("Warning: falha ao escrever CSV:", e)

    return metrics

@app.route("/status")
def status():
    """Retorna métricas em JSON (utilizar no frontend)."""
    m = collect_metrics()
    return jsonify(m)

# Rotas para servir arquivos estáticos (já coberto pelo static_folder),
# ainda assim deixamos rota raiz para index.html
@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")

# fornecer acesso direto a outras páginas (opcional)
@app.route("/<path:pth>")
def static_proxy(pth):
    # segurança leve: serve apenas arquivos que existem dentro STATIC_DIR
    full = os.path.join(STATIC_DIR, pth)
    if os.path.exists(full) and os.path.isfile(full):
        return send_from_directory(STATIC_DIR, pth)
    # fallback para index
    return send_from_directory(STATIC_DIR, "index.html")

if __name__ == "__main__":
    print(f"Rodando servidor em http://0.0.0.0:{PORT}  (servindo pasta: {STATIC_DIR})")
    # debug=False para produção; use reloader desligado em demos
    app.run(host="0.0.0.0", port=PORT, threaded=True)
