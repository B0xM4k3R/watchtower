#!/usr/bin/env python3
"""
Watchtower: Passive Network Traffic Analyzer
Final Version: Byte counting, tracker alerts, and silenced Scapy logs.
"""
import time
import threading
import sqlite3
import json
import os
import socket
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, HTTPServer
from scapy.all import sniff, IP, UDP, TCP, DNS, Raw, conf
from scapy.layers.tls.all import TLS

# Silence Scapy warnings
conf.verb = 0

DB_FILE = "watchtower.db"
PORT = 8081

SUSPICIOUS_DOMAINS = [
    "doubleclick.net", "google-analytics.com", "googletagmanager.com",
    "facebook.com", "scorecardresearch.com", "adservice.google.com",
    "analytics.yahoo.com", "hotjar.com"
]

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS dns (domain TEXT, count INTEGER DEFAULT 1, PRIMARY KEY (domain))")
    c.execute("CREATE TABLE IF NOT EXISTS sni (domain TEXT, count INTEGER DEFAULT 1, PRIMARY KEY (domain))")
    c.execute("""CREATE TABLE IF NOT EXISTS talkers (
        src TEXT, dst TEXT, packets INTEGER DEFAULT 1, bytes INTEGER DEFAULT 0,
        PRIMARY KEY (src, dst))""")
    conn.commit()
    conn.close()

buffer_dns = defaultdict(int)
buffer_sni = defaultdict(int)
buffer_talkers = defaultdict(lambda: [0, 0])
buffer_lock = threading.Lock()

ip_cache = {}
def get_hostname(ip):
    if ip in ip_cache:
        return ip_cache[ip]
    try:
        if ip.startswith("192.168.") or ip.startswith("10."):
            host = "Local Device"
        else:
            host = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        host = ""
    ip_cache[ip] = host
    return host

def extract_sni(packet):
    if packet.haslayer(TLS):
        tls = packet[TLS]
        if hasattr(tls, 'msg') and len(tls.msg) > 0:
            for msg in tls.msg:
                if getattr(msg, 'msgtype', 0) == 1: # Client Hello
                    if hasattr(msg, 'ext') and msg.ext:
                        for ext in msg.ext:
                            if getattr(ext, 'type', -1) == 0: # SNI Extension
                                if hasattr(ext, 'servernames') and ext.servernames:
                                    return ext.servernames[0].servername.decode('utf-8', 'ignore')
    return None

def process_packet(packet):
    if IP in packet:
        src, dst = packet[IP].src, packet[IP].dst
        pkt_len = len(packet)

        if not dst.startswith("224.") and not dst.endswith(".255") and not dst.startswith("239."):
            with buffer_lock:
                buffer_talkers[(src, dst)][0] += 1
                buffer_talkers[(src, dst)][1] += pkt_len

        if UDP in packet and packet[UDP].dport == 53 and DNS in packet and packet[DNS].qd:
            try:
                domain = packet[DNS].qd.qname.decode('utf-8').rstrip('.')
                with buffer_lock:
                    buffer_dns[domain] += 1
            except Exception:
                pass

        if (TCP in packet and packet[TCP].dport == 443) or (UDP in packet and packet[UDP].dport == 443):
            sni = extract_sni(packet)
            if sni:
                with buffer_lock:
                    buffer_sni[sni] += 1

def flush_buffer():
    global buffer_dns, buffer_sni, buffer_talkers
    while True:
        time.sleep(3)
        with buffer_lock:
            if not buffer_dns and not buffer_sni and not buffer_talkers:
                continue
            dns_copy, sni_copy, talkers_copy = buffer_dns, buffer_sni, buffer_talkers
            buffer_dns, buffer_sni, buffer_talkers = defaultdict(int), defaultdict(int), defaultdict(lambda: [0, 0])

        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        for d, count in dns_copy.items():
            c.execute("INSERT INTO dns (domain, count) VALUES (?, ?) ON CONFLICT(domain) DO UPDATE SET count = count + ?", (d, count, count))
        for d, count in sni_copy.items():
            c.execute("INSERT INTO sni (domain, count) VALUES (?, ?) ON CONFLICT(domain) DO UPDATE SET count = count + ?", (d, count, count))

        for (src, dst), (packets, bytes_count) in talkers_copy.items():
            c.execute("""INSERT INTO talkers (src, dst, packets, bytes) VALUES (?, ?, ?, ?)
                         ON CONFLICT(src, dst) DO UPDATE SET
                         packets = packets + ?, bytes = bytes + ?""",
                      (src, dst, packets, bytes_count, packets, bytes_count))
        conn.commit()
        conn.close()

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><title>Watchtower</title>
<style>
  body { background: #111d1d; color: #e4ece8; font: 16px/1.5 system-ui, sans-serif; max-width: 950px; margin: 0 auto; padding: 20px; }
  .header-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
  h1 { color: #e8923a; margin: 0; }
  button { background: #e8923a; color: #111d1d; border: none; padding: 8px 16px; border-radius: 6px; font-weight: bold; cursor: pointer; }
  button:hover { background: #f0a354; }
  .sub { color: #93a8a4; margin-top: 5px; }
  .card { background: #182827; border-radius: 8px; padding: 20px; margin-bottom: 20px; border: 1px solid #3f5552; }
  .alert-card { border-left: 4px solid #b4402b; background: #2a1a18; border-color: #b4402b; }
  .alert-card h2 { color: #f08a73; border-left-color: #f08a73; }
  h2 { font-size: 1.1rem; margin-top: 0; border-left: 3px solid #e8923a; padding-left: 10px; }
  table { width: 100%; border-collapse: collapse; margin-top: 10px; }
  th, td { text-align: left; padding: 8px; border-bottom: 1px solid #3f5552; font-size: 0.9rem; }
  th { color: #93a8a4; font-weight: normal; }
  .num { font-family: monospace; color: #5bbfa8; text-align: right; }
  .ip { font-family: monospace; font-size: 0.8rem; color: #93a8a4; }
  ul { margin: 0; padding-left: 20px; }
</style>
</head>
<body>
  <div class="header-bar">
    <div>
      <h1>Watchtower</h1>
      <div class="sub">Live local traffic for this device (updates every 2 seconds)</div>
    </div>
    <button onclick="clearData()">Clear Data (Reset Daily Total)</button>
  </div>

  <div id="alert-card" class="card alert-card" style="display:none;">
    <h2>⚠️ Suspicious / Tracker Traffic Detected</h2>
    <ul id="alert-list"></ul>
  </div>

  <div class="card">
    <h2>Total Bandwidth by Local Device</h2>
    <table id="device-table"><tr><th>Device</th><th style="text-align:right">Total Size</th></tr></table>
  </div>

  <div class="card">
    <h2>Top HTTPS Domains (SNI)</h2>
    <table id="sni-table"><tr><th>Domain</th><th style="text-align:right">Packets</th></tr></table>
  </div>

  <div class="card">
    <h2>Top Conversations (by Bytes)</h2>
    <table id="talker-table"><tr><th>Source</th><th>Destination</th><th style="text-align:right">Total Size</th></tr></table>
  </div>

  <script>
    function formatBytes(bytes) {
      if (bytes === 0) return '0 B';
      const k = 1024;
      const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    async function clearData() {
      if (!confirm("Clear all data? Use this to reset your daily bandwidth tracking.")) return;
      await fetch('/api/clear', {method: 'POST'});
      update();
    }

    async function update() {
      try {
        const r = await fetch('/api/stats');
        const data = await r.json();

        const alertCard = document.getElementById('alert-card');
        if (data.alerts.length > 0) {
          alertCard.style.display = 'block';
          document.getElementById('alert-list').innerHTML = data.alerts.map(a => `<li><b>${a}</b></li>`).join('');
        } else {
          alertCard.style.display = 'none';
        }

        const devTable = document.getElementById('device-table');
        devTable.innerHTML = '<tr><th>Device</th><th style="text-align:right">Total Size</th></tr>';
        data.devices.forEach(row => {
          devTable.innerHTML += `<tr><td>${row[0]}</td><td class="num"><b>${formatBytes(row[1])}</b></td></tr>`;
        });

        const sniTable = document.getElementById('sni-table');
        sniTable.innerHTML = '<tr><th>Domain</th><th style="text-align:right">Packets</th></tr>';
        data.sni.forEach(row => sniTable.innerHTML += `<tr><td>${row[0]}</td><td class="num">${row[1]}</td></tr>`);

        const talkTable = document.getElementById('talker-table');
        talkTable.innerHTML = '<tr><th>Source</th><th>Destination</th><th style="text-align:right">Total Size</th></tr>';
        data.talkers.forEach(row => {
          const srcHost = row[1] ? `<br><span class="ip">${row[1]}</span>` : '';
          const dstHost = row[3] ? `<br><span class="ip">${row[3]}</span>` : '';
          talkTable.innerHTML += `<tr><td>${row[0]}${srcHost}</td><td>${row[2]}${dstHost}</td><td class="num"><b>${formatBytes(row[5])}</b></td></tr>`;
        });
      } catch(e) {}
    }
    setInterval(update, 2000);
    update();
  </script>
</body>
</html>
"""

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_POST(self):
        if self.path == "/api/clear":
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("DELETE FROM dns")
            c.execute("DELETE FROM sni")
            c.execute("DELETE FROM talkers")
            conn.commit()
            conn.close()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"ok": true}')

    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(HTML.encode())
        elif self.path == "/api/stats":
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()

            query = """
                SELECT ip, SUM(bytes) as total FROM (
                    SELECT src as ip, bytes FROM talkers WHERE src LIKE '192.168.%' OR src LIKE '10.%'
                    UNION ALL
                    SELECT dst as ip, bytes FROM talkers WHERE dst LIKE '192.168.%' OR dst LIKE '10.%'
                ) GROUP BY ip ORDER BY total DESC LIMIT 10
            """
            devices_raw = c.execute(query).fetchall()
            devices = []
            for ip, total_bytes in devices_raw:
                devices.append((ip, total_bytes))

            sni = c.execute("SELECT domain, count FROM sni ORDER BY count DESC LIMIT 10").fetchall()
            dns = c.execute("SELECT domain, count FROM dns ORDER BY count DESC LIMIT 10").fetchall()
            raw_talkers = c.execute("SELECT src, dst, packets, bytes FROM talkers ORDER BY bytes DESC LIMIT 10").fetchall()
            conn.close()

            talkers = []
            for src, dst, packets, bytes_count in raw_talkers:
                talkers.append((src, get_hostname(src), dst, get_hostname(dst), packets, bytes_count))

            alerts = set()
            for domain, _ in sni + dns:
                for sus in SUSPICIOUS_DOMAINS:
                    if sus in domain:
                        alerts.add(domain)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"sni": sni, "dns": dns, "talkers": talkers, "devices": devices, "alerts": list(alerts)}).encode())
        else:
            self.send_response(404)
            self.end_headers()

if __name__ == "__main__":
    if not os.path.exists(DB_FILE):
        init_db()

    print("Starting Watchtower Sniffer...")
    threading.Thread(target=sniff, kwargs={"filter": "tcp or udp", "prn": process_packet, "store": False}, daemon=True).start()
    threading.Thread(target=flush_buffer, daemon=True).start()

    print(f"Dashboard running at http://localhost:{PORT}")
    print("Press Ctrl+C to stop.")
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
