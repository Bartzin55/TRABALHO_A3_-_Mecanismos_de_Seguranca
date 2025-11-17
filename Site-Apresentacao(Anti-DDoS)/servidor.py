#!/usr/bin/env python3
# servidor.py com mitigação simples de DDoS (token-bucket + blacklist + conn limit)
# Mantém: coletor em background, CSV, detecção NIC, /status e servir pasta site.
# Baseado no servidor anterior que você tinha. Referência: arquivo anterior. :contentReference[oaicite:1]{index=1}

from flask import Flask, jsonify, send_from_directory, request, abort, make_response
import psutil, time, os, csv
from threading import Lock, Thread
from collections import defaultdict
import logging

# ----------------- CONFIGURAÇÃO -----------------
STATIC_DIR = "site"
PORT = 8080
CSV_FILE = "metrics.csv"

# Mitigação
RATE_BASE = 5.0         # tokens por segundo permitidos por IP (sustained)
RATE_BURST = 20.0       # tokens máximos (burst)
BLACKLIST_THRESHOLD = 5 # quantas violações antes de ban temporário
BLACKLIST_SECONDS = 300 # tempo de bloqueio em segundos (5 min)
CONCURRENT_LIMIT = 10   # conexões simultâneas permitidas por IP

COLLECT_INTERVAL = 1.0  # segundos entre coletas

# log básico
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="")

# Locks
csv_lock = Lock()
metrics_lock = Lock()
rl_lock = Lock()
conn_lock = Lock()

# Snapshot de métricas (inicial)
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

# CSV init
if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "ts","cpu_percent","memory_percent","memory_used_mb","memory_total_mb",
            "tcp_established","bytes_sent","bytes_recv","network_usage_percent"
        ])

# net counters para cálculo de bytes/s
_prev_net = psutil.net_io_counters()
_prev_ts = time.time()

# detectar NIC capacity (Mbps -> bytes/s)
def detectar_capacidade_nic():
    try:
        stats = psutil.net_if_stats()
        for name, st in stats.items():
            if st.isup and st.speed and st.speed > 0:
                return int(st.speed * 125_000)  # Mbps -> bytes/s
    except Exception:
        pass
    return 125_000_000  # fallback 1Gbps

NIC_CAPACITY = detectar_capacidade_nic()

# ----------------- CONTROLE DE RATE-LIMIT (token bucket) -----------------
# Estruturas: tokens[ip] = (tokens, last_ts)
tokens = {}
violations = defaultdict(int)
blacklist = {}           # ip -> unblock_ts
concurrent_conns = defaultdict(int)  # ip -> conexões ativas

def allow_request(ip):
    """Retorna True se a requisição é permitida, False se deve ser bloqueada."""
    now = time.time()
    with rl_lock:
        # blacklist check
        if ip in blacklist:
            if now < blacklist[ip]:
                return False
            else:
                del blacklist[ip]
                violations[ip] = 0

        tok, last = tokens.get(ip, (RATE_BURST, now))
        # regen tokens
        elapsed = now - last
        tok = min(RATE_BURST, tok + elapsed * RATE_BASE)
        if tok >= 1.0:
            tok -= 1.0
            tokens[ip] = (tok, now)
            return True
        else:
            # violação
            tokens[ip] = (tok, now)
            violations[ip] += 1
            if violations[ip] >= BLACKLIST_THRESHOLD:
                blacklist[ip] = now + BLACKLIST_SECONDS
                logging.warning(f"Blacklisted {ip} for {BLACKLIST_SECONDS}s (violations={violations[ip]})")
            return False

def conn_acquire(ip):
    with conn_lock:
        if concurrent_conns[ip] >= CONCURRENT_LIMIT:
            return False
        concurrent_conns[ip] += 1
        return True

def conn_release(ip):
    with conn_lock:
        if concurrent_conns[ip] > 0:
            concurrent_conns[ip] -= 1

# ----------------- COLETOR EM BACKGROUND (mantido) -----------------
def collect_once():
    global _prev_net, _prev_ts
    ts = int(time.time())
    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory()

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

    # grava CSV de forma protegida
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
        logging.warning("falha ao escrever CSV: %s", e)

    with metrics_lock:
        _latest_metrics.update(metrics)

def collector_loop(interval=COLLECT_INTERVAL):
    # inicializa deltas
    psutil.cpu_percent(interval=None)
    global _prev_net, _prev_ts
    _prev_net = psutil.net_io_counters()
    _prev_ts = time.time()
    while True:
        try:
            collect_once()
        except Exception as e:
            logging.warning("Collector warning: %s", e)
        time.sleep(interval)

# ----------------- CACHE SIMPLES DE INDEX -----------------
_cached_index = None
_cached_index_mtime = 0
def cached_index():
    global _cached_index, _cached_index_mtime
    path = os.path.join(STATIC_DIR, "monitoramento.html")
    try:
        mtime = os.path.getmtime(path)
        if _cached_index is None or mtime != _cached_index_mtime:
            with open(path, "rb") as f:
                _cached_index = f.read()
            _cached_index_mtime = mtime
    except Exception:
        _cached_index = None
    return _cached_index

# ----------------- MIDDLEWARE FLASK: antes de cada requisição -----------------
@app.before_request
def before_req():
    # aceitar apenas GETs para páginas estáticas e /status
    ip = request.remote_addr or "unknown"
    # count concurrent connections (simple)
    if not conn_acquire(ip):
        logging.info("Conn limit exceeded for %s", ip)
        abort(make_response("Too many concurrent connections", 429))

    # aplicamos rate limiting apenas no endpoint /status (ponto crítico)
    if request.path == "/status":
        allowed = allow_request(ip)
        if not allowed:
            conn_release(ip)
            abort(make_response("Rate limit exceeded or blacklisted", 429))

# libera contagem de conexão após request (sempre)
@app.after_request
def after_req(response):
    ip = request.remote_addr or "unknown"
    conn_release(ip)
    return response

# ----------------- ROTAS -----------------
@app.route("/status")
def status():
    # retorna snapshot leve (rápido)
    with metrics_lock:
        return jsonify(dict(_latest_metrics))

@app.route("/")
def index():
    data = cached_index()
    if data is not None:
        return data, 200, {'Content-Type': 'text/html; charset=utf-8'}
    # fallback: servir arquivo normalmente
    return send_from_directory(STATIC_DIR, "monitoramento.html")

@app.route("/<path:pth>")
def proxy(pth):
    full = os.path.join(STATIC_DIR, pth)
    if os.path.exists(full) and os.path.isfile(full):
        return send_from_directory(STATIC_DIR, pth)
    return send_from_directory(STATIC_DIR, "monitoramento.html")

# rota administrativa simples para ver blacklist (apenas para demo/local)
@app.route("/_internal/blacklist")
def show_blacklist():
    # lista IPs atualmente bloqueados com tempo restante
    now = time.time()
    with rl_lock:
        out = {ip: int(until - now) for ip, until in blacklist.items() if until > now}
    return jsonify(out)

# ----------------- MAIN -----------------
if __name__ == "__main__":
    t = Thread(target=collector_loop, args=(COLLECT_INTERVAL,), daemon=True)
    t.start()
    logging.info("Servidor rodando em http://0.0.0.0:%d (NIC cap ~ %d bytes/s)", PORT, NIC_CAPACITY)
    # aceita conexões externas (0.0.0.0)
    app.run(host="0.0.0.0", port=PORT, threaded=True)
