import requests
import socket
import time
import threading
import json
import os

# ==========================================
# CONFIG
# ==========================================
CONFIG_FILE = "config.json"

DEFAULT_CONFIG = {
    "server_url": "http://192.168.0.10:8080",
    "udp_port": 9001,
    "tcp_port": 9002,
    "register_interval": 10,
    "node_id": socket.gethostname()
}


def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            cfg = json.load(f)
        return {**DEFAULT_CONFIG, **cfg}
    with open(CONFIG_FILE, "w") as f:
        json.dump(DEFAULT_CONFIG, f, indent=4)
    return DEFAULT_CONFIG


config = load_config()

SERVER_URL        = config["server_url"]
UDP_PORT          = config["udp_port"]
TCP_PORT          = config["tcp_port"]
REGISTER_INTERVAL = config["register_interval"]
NODE_ID           = config["node_id"]

current_rules = []
rules_lock    = threading.Lock()


# ==========================================
# IP LOCAL
# ==========================================
def get_my_ip():
    try:
        host = SERVER_URL.split("//")[1].split(":")[0]
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((host, 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return socket.gethostbyname(socket.gethostname())


# ==========================================
# REGISTRO
# ==========================================
def register():
    try:
        requests.post(
            f"{SERVER_URL}/register",
            json={"id": NODE_ID, "ip": get_my_ip()},
            timeout=5
        )
        print(f"[OK] Registrado como {NODE_ID} ({get_my_ip()})")
    except Exception as e:
        print(f"[ERR] Registro fallido: {e}")


# ==========================================
# REGLAS — se descargan del servidor
# ==========================================
def get_rules():
    global current_rules
    try:
        r = requests.get(f"{SERVER_URL}/rules", timeout=5)
        with rules_lock:
            current_rules = r.json()
        print(f"[OK] Reglas cargadas: {len(current_rules)}")
    except Exception as e:
        print(f"[ERR] No se pudieron cargar reglas: {e}")


# ==========================================
# MATCH — evalúa si una regla aplica
# ==========================================
def match_rule(rule, src_ip, dst_port, protocol):
    # Comodines: "*" y "0.0.0.0" para IP
    ip_match    = rule["src_ip"] in ("*", "0.0.0.0") or rule["src_ip"] == src_ip
    port_match  = str(rule["dst_port"]) == "*" or str(rule["dst_port"]) == str(dst_port)
    proto_match = rule["protocol"] == "*" or rule["protocol"].upper() == protocol.upper()
    return ip_match and port_match and proto_match


# ==========================================
# EVALUAR PAQUETE
# ==========================================
def evaluate_packet(src_ip, src_port, dst_port, protocol):
    with rules_lock:
        ordered = sorted(current_rules, key=lambda x: x.get("priority", 0), reverse=True)

    for rule in ordered:
        if match_rule(rule, src_ip, dst_port, protocol):
            action = rule["action"].upper()
            print(f"  → Regla #{rule['id']} coincide ({rule['src_ip']}:{rule['dst_port']} {rule['protocol']}) → {action}")
            return action

    print(f"  → Sin regla para {src_ip}:{src_port} → {dst_port}/{protocol} → PERMIT (default)")
    return "PERMIT"


# ==========================================
# EVENTOS — reportar al servidor
# ==========================================
def send_event(src_ip, src_port, dst_port, protocol, action, message=""):
    try:
        requests.post(
            f"{SERVER_URL}/event",
            json={
                "node_id":  NODE_ID,
                "src_ip":   src_ip,
                "src_port": src_port,
                "dst_ip":   get_my_ip(),
                "dst_port": dst_port,
                "protocol": protocol,
                "action":   action,
                "message":  message
            },
            timeout=3
        )
    except Exception as e:
        print(f"[ERR] send_event: {e}")


# ==========================================
# UDP
# ==========================================
def listen_udp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", UDP_PORT))
    print(f"[UDP] Escuchando en puerto {UDP_PORT}")

    while True:
        data, addr = sock.recvfrom(4096)
        src_ip, src_port = addr
        msg    = data.decode(errors="ignore")
        action = evaluate_packet(src_ip, src_port, UDP_PORT, "UDP")

        if action == "BLOCK":
            print(f"[BLOQUEADO] UDP {src_ip}:{src_port} → :{UDP_PORT}  msg='{msg}'")
            send_event(src_ip, src_port, UDP_PORT, "UDP", "BLOCK", msg)
            # UDP no tiene conexión: simplemente descartamos, no enviamos nada de vuelta
        else:
            print(f"[PERMITIDO] UDP {src_ip}:{src_port} → :{UDP_PORT}  msg='{msg}'")
            send_event(src_ip, src_port, UDP_PORT, "UDP", "PERMIT", msg)


# ==========================================
# TCP
# ==========================================
def handle_tcp(conn, addr):
    src_ip, src_port = addr
    try:
        data    = conn.recv(4096)
        msg     = data.decode(errors="ignore")
        action  = evaluate_packet(src_ip, src_port, TCP_PORT, "TCP")

        if action == "BLOCK":
            print(f"[BLOQUEADO] TCP {src_ip}:{src_port} → :{TCP_PORT}  msg='{msg}'")
            send_event(src_ip, src_port, TCP_PORT, "TCP", "BLOCK", msg)
            conn.send(b"BLOQUEADO")   # respuesta explícita para que el generador lo vea
        else:
            print(f"[PERMITIDO] TCP {src_ip}:{src_port} → :{TCP_PORT}  msg='{msg}'")
            send_event(src_ip, src_port, TCP_PORT, "TCP", "PERMIT", msg)
            conn.send(b"PERMITIDO")

    except Exception as e:
        print(f"[ERR] handle_tcp: {e}")
    finally:
        conn.close()


def listen_tcp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", TCP_PORT))
    sock.listen(10)
    print(f"[TCP] Escuchando en puerto {TCP_PORT}")

    while True:
        conn, addr = sock.accept()
        threading.Thread(target=handle_tcp, args=(conn, addr), daemon=True).start()


# ==========================================
# MAIN
# ==========================================
if __name__ == "__main__":
    print("=" * 50)
    print("  CLIENTE SDN")
    print(f"  Nodo:     {NODE_ID}")
    print(f"  Servidor: {SERVER_URL}")
    print(f"  TCP:      {TCP_PORT}   UDP: {UDP_PORT}")
    print("=" * 50)

    threading.Thread(target=listen_udp, daemon=True).start()
    threading.Thread(target=listen_tcp, daemon=True).start()

    while True:
        register()
        get_rules()
        time.sleep(REGISTER_INTERVAL)