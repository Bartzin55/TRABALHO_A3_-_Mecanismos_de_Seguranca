#!/usr/bin/env python3
# servidor.py — coleta métricas + mitigação L4 via nftables (ban permanente)
# - Detecta IPs que fazem muitas requests em curto intervalo
# - Adiciona regra nft: ip saddr <IP> drop  (ban no kernel)
# - Mantém collector em background, CSV, NIC detection, /status e pasta site

import os
import time
import csv
import logging
import subprocess
import shutil
from threading import Lock, Thread
from collections import defaultdict, deque

from flask import Flask, jsonify, send_from_directory, request, abort

import psutil

# ---------------- CONFIG ----------------
STATIC_DIR = "site"
PORT = 8080
CSV_FILE = "metrics.csv"

# Detecção de ataque (sliding window)
WINDOW_SECONDS = 5         # janela para contar requisições
THRESHOLD = 20             # requisições na janela => ban

COLLECT_INTERVAL = 1.0     # segundos entre coletas do collector

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="")

# ----------------- estado e locks -----------------
metrics_lock = Lock()
csv_lock = Lock()
requests_lock = Lock()
banned_lock = Lock()
_cached_index = None
_cached_index_mtime = 0

req_windows = defaultdict(lambda: deque())

banned_ips = set()

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

# ---------------- nft helpers ----------------
def nft_available():
    return bool(shutil.which("nft"))

def ensure_nft_table_chain():
    if not nft_available():
        logging.error("nft não encontrado no sistema.")
        return False
    try:
        p = subprocess.run(["nft", "list", "table", "inet", "filter"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if p.returncode != 0:
            subprocess.run(["sudo", "nft", "add", "table", "inet", "filter"], check=False)
            subprocess.run([
                "sudo", "nft", "add", "chain", "inet", "filter", "input",
                "{", "type", "filter", "hook", "input", "priority", "0;", "}"
            ], check=False)
            logging.info("Criada tabela/chain nft inet filter (criação automática).")
        return True
    except Exception as e:
        logging.error("Erro ao garantir tabela nft: %s", e)
        return False

def nft_block_ip(ip):
    if not ip or ip.startswith("127.") or ip == "localhost":
        logging.warning("Tentativa de bloquear IP local ignorada: %s", ip)
        return False
    if not nft_available():
        logging.error("nft não disponível; não é possível bloquear %s", ip)
        return False

    try:
        cmd = ["sudo", "nft", "add", "rule", "inet", "filter", "input", "ip", "saddr", ip, "drop"]
        subprocess.run(cmd, check=False)
        logging.info("Bloqueado no kernel (nft): %s", ip)
        return True

    except Exception as e:
        logging.error("Falha ao adicionar regra nft para %s : %s", ip, e)
        return False

# ---------------- DETECÇÃO / BAN ----------------
def register_request(ip):
    now = time.time()
    with requests_lock:
        dq = req_windows[ip]
        dq.append(now)
        cutoff = now - WINDOW_SECONDS
        while dq and dq[0] < cutoff:
            dq.popleft()

        if len(dq) >= THRESHOLD:
            with banned_lock:
                if ip in banned_ips:
                    return
                ensure_nft_table_chain()
                if nft_block_ip(ip):
                    banned_ips.add(ip)
                req_windows.pop(ip, None)
                logging.warning(
                    "IP %s banido permanentemente (trigger %d reqs in %ds).",
                    ip, THRESHOLD, WINDOW_SECONDS
                )

# ---------------- COLETOR EM BACKGROUND ----------------
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

# ---------------- CACHE SIMPLES INDEX ----------------
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

# ---------------- FLASK HOOKS ----------------
@app.before_request
def before_req():
    ip = request.remote_addr or "unknown"

    # bloqueio imediato se já banido
    with banned_lock:
        if ip in banned_ips:
            abort(404)

    # registrar TODAS as requisições
    register_request(ip)

@app.route("/status")
def status():
    with metrics_lock:
        return jsonify(dict(_latest_metrics))

@app.route("/")
def index():
    data = cached_index()
    if data is not None:
        return data, 200, {'Content-Type': 'text/html; charset=utf-8'}
    return send_from_directory(STATIC_DIR, "monitoramento.html")

@app.route("/<path:pth>")
def proxy(pth):
    full = os.path.join(STATIC_DIR, pth)
    if os.path.exists(full) and os.path.isfile(full):
        return send_from_directory(STATIC_DIR, pth)
    return send_from_directory(STATIC_DIR, "monitoramento.html")

@app.route("/_internal/blacklist")
def show_blacklist():
    with banned_lock:
        return jsonify(list(banned_ips))

# ---------------- MAIN ----------------
if __name__ == "__main__":
    t = Thread(target=collector_loop, args=(COLLECT_INTERVAL,), daemon=True)
    t.start()
    logging.info("Servidor rodando em http://0.0.0.0:%d (NIC cap ~ %d bytes/s)", PORT, NIC_CAPACITY)
    app.run(host="0.0.0.0", port=PORT, threaded=True)
