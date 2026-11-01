from flask import Flask, request, jsonify, send_from_directory
import socket
import concurrent.futures
import time
import os

app = Flask(__name__, static_folder="static")

# Common port service names
SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB", 9200: "Elasticsearch", 11211: "Memcached"
}

RISK_MAP = {
    23: "HIGH", 135: "MEDIUM", 139: "MEDIUM", 445: "MEDIUM",
    3389: "MEDIUM", 5900: "MEDIUM", 21: "MEDIUM", 6379: "HIGH",
    27017: "HIGH", 9200: "HIGH", 11211: "HIGH"
}

def scan_port(host, port, timeout=0.5):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            service = SERVICE_MAP.get(port, "Unknown")
            # Try banner grab
            banner = None
            try:
                s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s2.settimeout(0.5)
                s2.connect((host, port))
                s2.send(b"HEAD / HTTP/1.0\r\n\r\n")
                raw = s2.recv(256).decode("utf-8", errors="ignore").strip()
                banner = raw.split("\n")[0] if raw else None
                s2.close()
            except:
                pass
            return {
                "port": port,
                "state": "open",
                "service": service,
                "banner": banner,
                "risk": RISK_MAP.get(port, "LOW")
            }
    except:
        pass
    return None

def resolve_host(target):
    try:
        ip = socket.gethostbyname(target)
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = target
        return ip, hostname
    except:
        return None, None

@app.route("/")
def index():
    return send_from_directory("static", "index.html")

@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.json
    target = data.get("target", "").strip()
    port_range = data.get("port_range", "1-1024")
    
    if not target:
        return jsonify({"error": "No target specified"}), 400

    # Resolve host
    ip, hostname = resolve_host(target)
    if not ip:
        return jsonify({"error": f"Cannot resolve host: {target}"}), 400

    # Parse port range
    try:
        if "-" in port_range:
            start, end = port_range.split("-")
            ports = list(range(int(start), int(end) + 1))
        elif "," in port_range:
            ports = [int(p.strip()) for p in port_range.split(",")]
        else:
            ports = [int(port_range)]
        
        if len(ports) > 10000:
            return jsonify({"error": "Port range too large (max 10000)"}), 400
    except:
        return jsonify({"error": "Invalid port range format"}), 400

    start_time = time.time()
    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    elapsed = round(time.time() - start_time, 2)
    open_ports.sort(key=lambda x: x["port"])

    # Risk summary
    risk_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for p in open_ports:
        risk_counts[p["risk"]] += 1

    return jsonify({
        "target": target,
        "ip": ip,
        "hostname": hostname,
        "ports_scanned": len(ports),
        "open_ports": open_ports,
        "elapsed": elapsed,
        "risk_summary": risk_counts
    })

@app.route("/api/quick-presets")
def quick_presets():
    return jsonify({
        "presets": [
            {"name": "Top 20 Common", "range": "21,22,23,25,53,80,110,139,143,443,445,3306,3389,5432,5900,6379,8080,8443,27017,9200"},
            {"name": "Web Ports", "range": "80,443,8080,8443,8888,9000,9090,3000,4000,5000"},
            {"name": "Full Standard", "range": "1-1024"},
            {"name": "Extended", "range": "1-10000"},
        ]
    })

if __name__ == "__main__":
    os.makedirs("static", exist_ok=True)
    print("NetScan RTAF running at http://localhost:5000")
    app.run(debug=True, host="0.0.0.0", port=5000)
