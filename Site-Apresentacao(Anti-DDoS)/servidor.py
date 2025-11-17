#!/usr/bin/env python3
# servidor.py com mitigação simples de DDoS (token-bucket + blacklist + conn limit + nftables DROP)
# Mantém: coletor em background, CSV, detecção NIC, /status e servir pasta site.

from flask import Flask, jsonify, send_from_directory, request, abort, make_response
import psutil, time, os, csv, subprocess
from threading import Lock, Thread
from collections import defaultdict
import logging

# ----------------- CONFIGURAÇÃO -----------------
STATIC_DIR = "site"
PORT = 8080
CSV_FILE = "metrics.csv"

# Mitigação
RATE_BASE = 5.0         # tokens por segundo permitidos por IP
RATE_BURST = 20.0       # tokens máximos (burst)
BLACKLIST_THRESHOLD = 5 # violações antes de aplicar firewall
CONCURRENT_LIMIT = 10   # conexões simultâneas permitidas por IP
BLACKLIST_SECONDS = 300 # usado só para visualização / camada L7

COLLECT_INTERVAL = 1.0  # segundos entre coletas

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="")

# ----------------- FIREWALL (NFTABLES) -----------------

def nft_setup():
    """Cria tabela e chain caso não existam."""
    try:
        subprocess.run(["sudo", "nft", "add", "table", "inet", "filter"], stderr=subprocess.DEVNULL)
        subprocess.run([
            "sudo", "nft", "add", "chain", "inet", "filter", "input",
            "{", "type", "filter", "hook", "input", "priority", "0", ";", "}"
        ], stderr=subprocess.DEVNULL)
    except Exception as e:
        logging.error(f"Erro ao configurar nftables: {e}")

def nft_block_ip(ip):
    """Bloqueia o IP no firewall (DROP) de forma permanente."""
    if ip.startswith("127.") or ip == "localhost":
        return  # nunca bloquear localhost
    try:
        cmd = [
            "sudo", "nft", "add", "rule", "inet", "filter", "input",
            "ip", "saddr", ip, "drop"
        ]
        subprocess.run(cmd, stderr=subprocess.DEVNULL)
        os.system(f"nft add rule inet filter input ip saddr {ip} drop")
        logging.warning(f"[FIREWALL] IP bloqueado via nftables: {ip}")
    except Exception as e:
        logging.error(f"Erro ao bloquear IP no nftables: {e}")

# Inicializar nftables
nft_setup()

# ----------------- CONTROLE DE RATE-LIMIT -----------------

tokens = {}
violations = defaultdict(int)
blacklist = {}  
concurrent_conns = defaultdict(int)

def allow_request(ip):
    """Controle do token-bucket L7."""
    now = time.time()
    if ip in blacklist and now < blacklist[ip]:
        return False

    tok, last = tokens.get(ip, (RATE_BURST, now))
    elapsed = now - last
    tok = min(RATE_BURST, tok + elapsed * RATE_BASE)

    if tok >= 1:
        tokens[ip] = (tok - 1, now)
        return True

    # violação
    tokens[ip] = (tok, now)
    violations[ip] += 1

    if violations[ip] >= BLACKLIST_THRESHOLD:
        blacklist[ip] = now + BLACKLIST_SECONDS
        logging.warning(f"[DEFESA L7] Blacklist lógico: {ip}")
        nft_block_ip(ip)  # Defesa real aqui (L4)

    return False

def conn_acquire(ip):
    if concurrent_conns[ip] >= CONCURRENT_LIMIT:
        return False
    concurrent_conns[ip] += 1
    return True

def conn_release(ip):
    if concurrent_conns[ip] > 0:
        concurrent_conns[ip] -= 1

# ----------------- COLETOR -----------------

csv_lock = Lock()
metrics_lock = Lock()

_prev_net = psutil.net_io_counters()
_prev_ts = time.time()

def detectar_capacidade_nic():
    try:
        stats = psutil.net_if_stats()
        for name, st in stats.items():
            if st.isup and st.speed and st.speed > 0:
                return int(st.speed * 125_000)
    except:
        pass
    return 125_000_000

NIC_CAPACITY = detectar_capacidade_nic()

_latest_metrics = {
    "timestamp": int(time.time()),
    "cpu_percent": 0,
    "memory_percent": 0,
    "memory_used_mb": 0,
    "memory_total_mb": 0,
    "tcp_established": 0,
    "bytes_sent_per_s": 0,
    "bytes_recv_per_s": 0,
    "network_usage_percent": 0
}

def collect_once():
    global _prev_net, _prev_ts

    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory()

    try:
        conns = psutil.net_connections(kind='inet')
        tcp_est = sum(1 for c in conns if c.status == 'ESTABLISHED')
    except:
        tcp_est = 0

    net = psutil.net_io_counters()
    now = time.time()
    delta = max(1e-6, now - _prev_ts)

    sent_s = (net.bytes_sent - _prev_net.bytes_sent) / delta
    recv_s = (net.bytes_recv - _prev_net.bytes_recv) / delta
    usage = min(100, (sent_s + recv_s) / NIC_CAPACITY * 100)

    _prev_net = net
    _prev_ts = now

    metrics = {
        "timestamp": int(now),
        "cpu_percent": round(cpu, 2),
        "memory_percent": round(mem.percent, 2),
        "memory_used_mb": round(mem.used/1024/1024, 2),
        "memory_total_mb": round(mem.total/1024/1024, 2),
        "tcp_established": tcp_est,
        "bytes_sent_per_s": round(sent_s, 1),
        "bytes_recv_per_s": round(recv_s, 1),
        "network_usage_percent": round(usage, 1)
    }

    with metrics_lock:
        _latest_metrics.update(metrics)

def collector_loop():
    psutil.cpu_percent(interval=None)
    while True:
        collect_once()
        time.sleep(COLLECT_INTERVAL)

# ----------------- FLASK -----------------

@app.before_request
def before_req():
    ip = request.remote_addr

    if not conn_acquire(ip):
        abort(429)

    if request.path == "/status":
        if not allow_request(ip):
            conn_release(ip)
            abort(429)

@app.after_request
def after_req(resp):
    ip = request.remote_addr
    conn_release(ip)
    return resp

@app.route("/status")
def status():
    with metrics_lock:
        return jsonify(_latest_metrics)

@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")

@app.route("/<path:pth>")
def static_files(pth):
    return send_from_directory(STATIC_DIR, pth)

# ----------------- MAIN -----------------
if __name__ == "__main__":
    Thread(target=collector_loop, daemon=True).start()
    logging.info(f"Servidor iniciado em http://0.0.0.0:{PORT}")
    app.run(host="0.0.0.0", port=PORT, threaded=True)
