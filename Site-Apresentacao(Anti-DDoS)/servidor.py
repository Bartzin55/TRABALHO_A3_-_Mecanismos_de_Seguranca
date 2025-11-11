# servidor_defesa.py
"""
Servidor Flask com defesa simples contra floods:
- rate limiting por IP (janela deslizante)
- limite de requisições simultâneas por IP
- blacklist temporária para IPs que exageram
- coleta de métricas (psutil) e gravação em CSV (metrics.csv)

Boa para demonstração em rede isolada (laboratório).
Não substitui mitigação profissional (nginx + iptables + CDN).
"""

from flask import Flask, jsonify, send_from_directory, request, make_response
import psutil, time, os, csv
from threading import Lock
from collections import deque, defaultdict

STATIC_DIR = "site"
PORT = 8080
CSV_FILE = "metrics.csv"

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="")

# ---------- defesa: parâmetros (ajuste para a demo) ----------
RATE_WINDOW_SECONDS = 10        # janela para contar requests
RATE_MAX_REQUESTS = 12          # max requests por janela por IP
CONN_LIMIT_PER_IP = 6           # max requisições simultâneas por IP
GLOBAL_CONCURRENT_LIMIT = 80    # limite global simultâneo (proteção básica)
BAN_THRESHOLD = 4               # quantas vezes excedeu o limite que vira ban
BAN_SECONDS = 120               # ban temporário (2 minutos)
# --------------------------------------------------------------

# estruturas em memória (thread-safe com locks)
ip_request_times = defaultdict(lambda: deque())  # ip -> deque of timestamps
ip_active_requests = defaultdict(int)           # ip -> int active requests
ip_excess_counts = defaultdict(int)             # ip -> count of violations
banned_ips = {}                                  # ip -> expire_timestamp

global_active_lock = Lock()
global_active_requests = 0

data_lock = Lock()  # para escrever CSV e manipular estruturas

# CSV init
if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ts","cpu_percent","memory_percent","memory_used_mb","memory_total_mb",
                    "tcp_established","bytes_sent","bytes_recv"])

# estado para bytes/s
prev_net = psutil.net_io_counters()
prev_ts = time.time()

def client_ip():
    """Pega IP do cliente de forma básica; suporta X-Real-IP se estiver atrás de proxy."""
    x = request.headers.get("X-Real-IP") or request.headers.get("X-Forwarded-For")
    if x:
        # X-Forwarded-For pode conter lista
        return x.split(",")[0].strip()
    return request.remote_addr or "unknown"

def is_banned(ip):
    now = time.time()
    exp = banned_ips.get(ip)
    if exp and exp > now:
        return True
    if exp and exp <= now:
        # ban expirou
        with data_lock:
            banned_ips.pop(ip, None)
            ip_excess_counts.pop(ip, None)
        return False
    return False

def register_request_time(ip):
    now = time.time()
    dq = ip_request_times[ip]
    dq.append(now)
    # pop old timestamps
    while dq and (now - dq[0] > RATE_WINDOW_SECONDS):
        dq.popleft()

def rate_exceeded(ip):
    dq = ip_request_times[ip]
    return len(dq) > RATE_MAX_REQUESTS

def record_excess(ip):
    # incrementa contador de excessos; se ultrapassar BAN_THRESHOLD, bane
    ip_excess_counts[ip] += 1
    if ip_excess_counts[ip] >= BAN_THRESHOLD:
        banned_until = time.time() + BAN_SECONDS
        banned_ips[ip] = banned_until
        return True
    return False

def collect_metrics():
    """Coleta métricas e grava CSV (similar ao anterior)."""
    global prev_net, prev_ts
    ts = int(time.time())
    cpu = psutil.cpu_percent(interval=0.03)
    mem = psutil.virtual_memory()
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
        "cpu_percent": round(cpu, 2),
        "memory_percent": round(mem.percent, 2),
        "memory_used_mb": round(mem.used / 1024 / 1024, 2),
        "memory_total_mb": round(mem.total / 1024 / 1024, 2),
        "tcp_established": tcp_est,
        "bytes_sent_per_s": round(bytes_sent_per_s, 1),
        "bytes_recv_per_s": round(bytes_recv_per_s, 1)
    }

    # grava CSV (append)
    try:
        with data_lock:
            with open(CSV_FILE, "a", newline="") as f:
                w = csv.writer(f)
                w.writerow([ts, metrics["cpu_percent"], metrics["memory_percent"],
                            metrics["memory_used_mb"], metrics["memory_total_mb"],
                            metrics["tcp_established"], net.bytes_sent, net.bytes_recv])
    except Exception as e:
        print("Warning: falha ao escrever CSV:", e)

    return metrics

# ---------- hooks que implementam as proteções ----------
@app.before_request
def before_request_protect():
    global global_active_requests
    ip = client_ip()

    # permitir rota de arquivos estáticos sem proteção excessiva? Ainda protegemos tudo.
    # checa lista de ban
    if is_banned(ip):
        # retorna 429
        return make_response(("429 Too Many Requests (banned)", 429))

    # controle global de concorrência
    with global_active_lock:
        if global_active_requests >= GLOBAL_CONCURRENT_LIMIT:
            return make_response(("503 Service Unavailable (global concurrency limit)", 503))
        global_active_requests += 1

    # controle por-IP de requisições simultâneas
    with data_lock:
        ip_active_requests[ip] += 1
        if ip_active_requests[ip] > CONN_LIMIT_PER_IP:
            # registro de excesso
            exceed = record_excess(ip)
            # decrement global & ip counters antes de responder
            with global_active_lock:
                global_active_requests -= 1
            ip_active_requests[ip] -= 1
            if exceed:
                msg = f"429 Too Many Requests - you have been temporarily banned for {BAN_SECONDS}s"
                return make_response((msg, 429))
            else:
                # responder 429 com Retry-After simples
                resp = make_response(("429 Too Many Requests - slow down", 429))
                resp.headers['Retry-After'] = str(RATE_WINDOW_SECONDS)
                return resp

    # rate limiting por janela: registramos o tempo aqui (antes de processar)
    with data_lock:
        register_request_time(ip)
        if rate_exceeded(ip):
            # excedeu o limite de requests na janela -> conta excesso e talvez ban
            exceed = record_excess(ip)
            # desfazer incrementos acima antes de responder
            with global_active_lock:
                global_active_requests -= 1
            ip_active_requests[ip] -= 1
            if exceed:
                return make_response((f"429 Too Many Requests - banned for {BAN_SECONDS}s", 429))
            else:
                resp = make_response(("429 Too Many Requests - rate limit", 429))
                resp.headers['Retry-After'] = str(RATE_WINDOW_SECONDS)
                return resp
    # se chegou até aqui, request segue normalmente

@app.after_request
def after_request_cleanup(response):
    # decrementa contadores de concorrência (se possível)
    try:
        ip = client_ip()
        with data_lock:
            if ip_active_requests.get(ip, 0) > 0:
                ip_active_requests[ip] -= 1
    except Exception:
        pass
    with global_active_lock:
        global global_active_requests
        if global_active_requests > 0:
            global_active_requests -= 1
    return response

# ---------- rotas ----------
@app.route("/status")
def status():
    """Rota de métricas (JSON)."""
    m = collect_metrics()
    return jsonify(m)

@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")

@app.route("/<path:pth>")
def static_proxy(pth):
    # Serve arquivos estáticos da pasta site/
    full = os.path.join(STATIC_DIR, pth)
    if os.path.exists(full) and os.path.isfile(full):
        return send_from_directory(STATIC_DIR, pth)
    return send_from_directory(STATIC_DIR, "index.html")

# ---------- utilitário para ver estado da defesa (apenas para debug/demo) ----------
@app.route("/_debug/defense_status")
def debug_defense_status():
    """Mostra info resumida (JSON) sobre bloqueios - útil para slides."""
    with data_lock:
        now = time.time()
        banned_list = {ip: int(exp - now) for ip, exp in banned_ips.items() if exp > now}
        short = {
            "global_active_requests": global_active_requests,
            "banned_count": len(banned_list),
            "banned_ips": banned_list,
        }
    return jsonify(short)

# ---------- main ----------
if __name__ == "__main__":
    print(f"Rodando servidor com defesa simples em http://0.0.0.0:{PORT} (servindo pasta: {STATIC_DIR})")
    app.run(host="0.0.0.0", port=PORT, threaded=True)
