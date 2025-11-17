#!/usr/bin/env python3
# servidor.py — coleta métricas + mitigação L3/L4 via nftables (rate-limit + blacklist)
# Rodar como root: sudo python3 servidor.py

import os
import sys
import time
import csv
import logging
import subprocess
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

# nftables rate limits (ajuste conforme necessário)
TCP_HTTP_RATE = "50/second"    # novas conexões TCP HTTP (SYN/novas conexões)
TCP_HTTP_BURST = 100
UDP_RATE = "20/second"         # UDP flood na porta
GENERIC_RATE = "1000/second"   # fallback: limite extremo por IP geral

COLLECT_INTERVAL = 1.0     # segundos entre coletas do collector

# logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="")

# ---------------- safety: exigir root ----------------
if os.geteuid() != 0:
    print("Erro: este servidor deve ser executado como root (sudo).")
    print("Execute assim:\n   sudo python3 servidor.py\n")
    sys.exit(1)

# ----------------- estado e locks -----------------
metrics_lock = Lock()
csv_lock = Lock()
requests_lock = Lock()
banned_lock = Lock()

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
            if st.isup and getattr(st, "speed", None) and st.speed > 0:
                return int(st.speed * 125_000)  # Mbps -> bytes/s
    except Exception:
        pass
    return 125_000_000  # fallback 1Gbps

NIC_CAPACITY = detectar_capacidade_nic()

# ---------------- nft helpers ----------------
def nft_available():
    try:
        subprocess.run(["nft", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False

def run_nft_script(script_text):
    """Aplica um script nft via stdin (nft -f -)"""
    try:
        p = subprocess.run(["nft", "-f", "-"], input=script_text, text=True, capture_output=True)
        if p.returncode != 0:
            logging.error("nft deu erro: %s", p.stderr.strip())
            return False, p.stderr.strip()
        return True, p.stdout.strip()
    except Exception as e:
        logging.exception("falha ao rodar nft: %s", e)
        return False, str(e)

def ensure_nft_table_chain():
    """
    Cria tabela inet filter, set blacklist, e chain input com regras de rate-limit.
    Se já existir, tenta não sobrescrever (mas garante que exista a set e as regras base).
    """
    if not nft_available():
        logging.error("nft não encontrado no sistema. Instale nftables.")
        return False

    # script idempotente: cria tabela se não existe; cria set se não existe; adiciona chain se não existe
    script = f"""
table inet filter {{
    # set de blacklist para bloqueios por IP (usado por Python também)
    set blacklist {{
        type ipv4_addr;
        # flags timeout;  # se quiser bans temporários, ajustar via elementos com timeout
    }}

    chain input {{
        type filter hook input priority 0; policy accept;

        # drop blacklisted IPs
        ip saddr @blacklist drop;

        # descartar pacotes inválidos
        ct state invalid drop;

        # Proteções específicas para porta do servidor (HTTP em 8080)
        tcp dport {PORT} ct state new limit rate over {TCP_HTTP_RATE} drop
        # burst opcional pode ser adicionado via "limit rate over X/second burst Y" em versões
        udp dport {PORT} limit rate over {UDP_RATE} drop

        # limitação de novas conexões em geral (evita SYN flood)
        ct state new limit rate over {GENERIC_RATE} drop
    }}
}}
"""
    ok, out = run_nft_script(script)
    if not ok:
        logging.error("Falha ao aplicar regras nft base: %s", out)
        return False
    logging.info("Tabela/chain/set nft garantidos.")
    return True

def nft_block_ip(ip):
    """Adiciona IP ao set blacklist (permanente até remoção manual)."""
    try:
        cmd = ["nft", "add", "element", "inet", "filter", "blacklist", "{", ip, "}"]
        p = subprocess.run(cmd, capture_output=True, text=True)
        if p.returncode != 0:
            # pode já existir; tentar verificar/ignorar
            if "already exists" in p.stderr.lower() or "exists" in p.stderr.lower():
                logging.info("IP %s já presente no set blacklist.", ip)
                return True
            logging.error("Erro adicionando IP ao set: %s", p.stderr.strip())
            return False
        logging.info("IP %s adicionado ao set blacklist (nft).", ip)
        return True
    except Exception as e:
        logging.exception("falha em nft_block_ip: %s", e)
        return False

def nft_unblock_ip(ip):
    try:
        cmd = ["nft", "delete", "element", "inet", "filter", "blacklist", "{", ip, "}"]
        p = subprocess.run(cmd, capture_output=True, text=True)
        if p.returncode != 0:
            logging.error("Erro removendo IP do set: %s", p.stderr.strip())
            return False
        logging.info("IP %s removido do set blacklist.", ip)
        return True
    except Exception as e:
        logging.exception("falha em nft_unblock_ip: %s", e)
        return False

def nft_list_blacklist():
    try:
        p = subprocess.run(["nft", "list", "set", "inet", "filter", "blacklist"], capture_output=True, text=True)
        if p.returncode != 0:
            return []
        out = p.stdout
        # saída tem linhas como: elements = { 1.2.3.4, 5.6.7.8 }
        if "elements" in out:
            start = out.find("{")
            end = out.find("}", start)
            if start != -1 and end != -1:
                inner = out[start+1:end].strip()
                if not inner:
                    return []
                # split por vírgula e limpar
                ips = [x.strip() for x in inner.split(",") if x.strip()]
                return ips
        return []
    except Exception:
        return []

# ---------------- DETECÇÃO / BAN (em memória + nft) ----------------
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
                ok = nft_block_ip(ip)
                if ok:
                    banned_ips.add(ip)
                req_windows.pop(ip, None)
                logging.warning("IP %s banido permanentemente (trigger %d reqs in %ds).", ip, THRESHOLD, WINDOW_SECONDS)

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

# ---------------- FLASK HOOKS / ROTAS ----------------
@app.before_request
def before_req():
    ip = request.remote_addr or "unknown"

    # se já banido em memória, devolver 404 rápido
    with banned_lock:
        if ip in banned_ips:
            abort(404)

    # registrar TODAS as requisições que chegam ao Flask (HTTP válidas)
    register_request(ip)

@app.route("/status")
def status():
    with metrics_lock:
        return jsonify(dict(_latest_metrics))

@app.route("/_internal/blacklist")
def show_blacklist():
    # junta lista em memória + set nft para ver consistência
    nftlist = nft_list_blacklist()
    with banned_lock:
        mem = list(banned_ips)
    return jsonify({"in_memory": mem, "nft_set": nftlist})

@app.route("/_internal/unblock/<ip>")
def unblock(ip):
    # rota interna para remover do blacklist (cuidado em prod)
    ok = nft_unblock_ip(ip)
    if ok:
        with banned_lock:
            banned_ips.discard(ip)
        return jsonify({"result": "unblocked", "ip": ip})
    return jsonify({"result": "error", "msg": "failed to remove"}), 500

@app.route("/_internal/block/<ip>")
def block(ip):
    ok = nft_block_ip(ip)
    if ok:
        with banned_lock:
            banned_ips.add(ip)
        return jsonify({"result": "blocked", "ip": ip})
    return jsonify({"result": "error", "msg": "failed to add"}), 500

@app.route("/")
def index_route():
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

# ---------------- MAIN ----------------
if __name__ == "__main__":
    logging.info("Iniciando servidor — garantindo nftables e inicializando collector.")
    if not ensure_nft_table_chain():
        logging.error("Falha ao garantir regras nft base. Saindo.")
        sys.exit(1)

    # opcional: carregar blacklist existente do nft no memoria
    existing = nft_list_blacklist()
    with banned_lock:
        for ip in existing:
            banned_ips.add(ip)

    t = Thread(target=collector_loop, args=(COLLECT_INTERVAL,), daemon=True)
    t.start()

    logging.info("Servidor rodando em http://0.0.0.0:%d (NIC cap ~ %d bytes/s)", PORT, NIC_CAPACITY)
    app.run(host="0.0.0.0", port=PORT, threaded=True)
