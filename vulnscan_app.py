#!/usr/bin/env python3
"""Easy VulnScanner: panel web para lanzar escaneos con nmap y generar reportes.

Usar solo sobre infraestructura propia o con autorizacion escrita del dueño.
"""
import datetime
import hmac
import html
import ipaddress
import os
import re
import sqlite3
import subprocess
import threading
import time
import uuid
from pathlib import Path

import requests as req
from flask import Flask, Response, jsonify, redirect, request, send_file, session

# --- Configuracion (variables de entorno) -----------------------------------
SECRET = os.environ.get('VULNSCAN_SECRET', '')
USERNAME = os.environ.get('VULNSCAN_USER', 'admin')
PASSWORD = os.environ.get('VULNSCAN_PASS', '')
HOST = os.environ.get('VULNSCAN_HOST', '127.0.0.1')
PORT = int(os.environ.get('VULNSCAN_PORT', '5000'))
DATA_DIR = Path(os.environ.get('VULNSCAN_DATA_DIR',
                               str(Path(__file__).resolve().parent / 'data')))

if not SECRET:
    raise SystemExit('Falta VULNSCAN_SECRET en el entorno. Ver .env.example')
if len(PASSWORD) < 12:
    raise SystemExit('VULNSCAN_PASS no esta definida o tiene menos de 12 caracteres')

app = Flask(__name__)
app.secret_key = SECRET
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax')

DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / 'vulnscan.db'
scans = {}

INTENSITIES = {'rapido': '-T4', 'normal': '-T3', 'sigiloso': '-T1'}
HOST_RE = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$')
PORTS_RE = re.compile(r'^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$')

# --- Limite de intentos de login ---------------------------------------------
LOGIN_MAX_FAILS = 5
LOGIN_WINDOW = 900  # segundos
_login_fails = {}
_login_lock = threading.Lock()


def login_blocked(ip):
    cutoff = time.time() - LOGIN_WINDOW
    with _login_lock:
        recent = [t for t in _login_fails.get(ip, []) if t > cutoff]
        _login_fails[ip] = recent
        return len(recent) >= LOGIN_MAX_FAILS


def register_login_fail(ip):
    with _login_lock:
        _login_fails.setdefault(ip, []).append(time.time())


def clear_login_fails(ip):
    with _login_lock:
        _login_fails.pop(ip, None)


def credentials_ok(user, pwd):
    ok_user = hmac.compare_digest(user.encode(), USERNAME.encode())
    ok_pass = hmac.compare_digest(pwd.encode(), PASSWORD.encode())
    return ok_user and ok_pass


# --- Validacion de entrada ---------------------------------------------------
def validate_target(t):
    """Acepta IP, rango CIDR u hostname. Devuelve el valor o None."""
    if not isinstance(t, str):
        return None
    t = t.strip()
    if not t or len(t) > 253 or t.startswith('-'):
        return None
    try:
        if '/' in t:
            ipaddress.ip_network(t, strict=False)
        else:
            ipaddress.ip_address(t)
        return t
    except ValueError:
        pass
    return t if HOST_RE.match(t) else None


def validate_ports(p):
    """Acepta lista/rangos de puertos (ej: 22,80,1-1024). Devuelve el valor o None."""
    if not isinstance(p, str):
        return None
    p = p.replace(' ', '')
    if not PORTS_RE.match(p):
        return None
    for part in re.split(r'[,-]', p):
        if int(part) > 65535:
            return None
    return p


# --- Autenticacion ------------------------------------------------------------
LOGIN_HTML = """<!DOCTYPE html><html><head><meta charset="UTF-8"><title>VULNSCAN - Login</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#0a0d0a;color:#c8d8c8;font-family:'Segoe UI',sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}
.box{background:#0d110d;border:1px solid #1a2a1a;padding:40px;width:320px}
.logo{font-size:22px;font-weight:700;letter-spacing:4px;text-align:center;margin-bottom:28px}.logo span{color:#00ff88}
label{font-size:9px;letter-spacing:2px;color:#3a6a3a;display:block;margin-bottom:5px;font-family:monospace}
input{width:100%;background:#060906;border:1px solid #1a2a1a;color:#c8d8c8;padding:8px 10px;font-family:monospace;font-size:12px;outline:none;margin-bottom:14px}
input:focus{border-color:#00ff88}
button{width:100%;background:transparent;border:1px solid #00ff88;color:#00ff88;padding:9px;font-family:monospace;font-size:11px;letter-spacing:3px;cursor:pointer}
button:hover{background:#00ff88;color:#0a0d0a}
.err{color:#ef4444;font-family:monospace;font-size:11px;text-align:center;margin-bottom:12px}</style></head>
<body><div class="box">
<div class="logo">VULN<span>SCAN</span></div>
<form method="POST">
__ERROR__
<label>USUARIO</label><input type="text" name="username" autofocus>
<label>PASSWORD</label><input type="password" name="password">
<button type="submit">INGRESAR</button>
</form></div></body></html>"""


@app.before_request
def check_auth():
    if request.path == '/login':
        return
    if not session.get('logged_in'):
        return redirect('/login')


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ''
    status = 200
    if request.method == 'POST':
        ip = request.remote_addr or 'unknown'
        if login_blocked(ip):
            error = 'Demasiados intentos fallidos. Espera 15 minutos.'
            status = 429
        elif credentials_ok(request.form.get('username', ''), request.form.get('password', '')):
            clear_login_fails(ip)
            session.clear()
            session['logged_in'] = True
            session['username'] = USERNAME
            return redirect('/')
        else:
            register_login_fail(ip)
            error = 'Usuario o password incorrectos'
    block = f'<div class="err">{html.escape(error)}</div>' if error else ''
    return Response(LOGIN_HTML.replace('__ERROR__', block), status=status, mimetype='text/html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


# --- Base de datos ------------------------------------------------------------
def db_init():
    con = sqlite3.connect(DB_PATH)
    con.execute("""CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY, target TEXT, ports TEXT, intensity TEXT, status TEXT,
        cve_count INTEGER DEFAULT 0, port_count INTEGER DEFAULT 0,
        warn_count INTEGER DEFAULT 0, os_detected TEXT, scan_status TEXT,
        report_path TEXT, raw_output TEXT, created_at TEXT, finished_at TEXT)""")
    con.commit()
    con.close()


def db_insert(scan_id, target, ports, intensity):
    con = sqlite3.connect(DB_PATH)
    con.execute("INSERT OR IGNORE INTO scans (id,target,ports,intensity,status,created_at) VALUES (?,?,?,?,?,?)",
                (scan_id, target, ports, intensity, 'running', datetime.datetime.now().isoformat()))
    con.commit()
    con.close()


def db_update(scan_id, status, cve_count, port_count, warn_count, os_detected, scan_status, report_path, raw_output):
    con = sqlite3.connect(DB_PATH)
    con.execute("""UPDATE scans SET status=?,cve_count=?,port_count=?,warn_count=?,
        os_detected=?,scan_status=?,report_path=?,raw_output=?,finished_at=? WHERE id=?""",
                (status, cve_count, port_count, warn_count, os_detected, scan_status, report_path,
                 raw_output[:50000], datetime.datetime.now().isoformat(), scan_id))
    con.commit()
    con.close()


def db_get_all():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    rows = con.execute("SELECT * FROM scans WHERE status='done' ORDER BY created_at DESC").fetchall()
    con.close()
    return [dict(r) for r in rows]


def load_scans_from_db():
    for r in db_get_all():
        scans[r['id']] = {
            'status': 'done', 'output': [], 'target': r['target'],
            'report_path': r['report_path'],
            'summary': {
                'target': r['target'], 'ports': r['port_count'],
                'cves': r['cve_count'], 'status': r['scan_status'] or 'CLEAN',
                'os': (r['os_detected'] or '')[:35],
                'date': (r['created_at'] or '')[:16].replace('T', ' ')
            }
        }


db_init()


# --- CVEs (NVD) ----------------------------------------------------------------
def get_latest_cves(limit=12):
    try:
        r = req.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={"resultsPerPage": limit, "cvssV3Severity": "CRITICAL"}, timeout=8)
        out = []
        for item in r.json().get('vulnerabilities', []):
            cve = item.get('cve', {})
            cid = cve.get('id', '')
            desc = next((d['value'][:120] + '...' for d in cve.get('descriptions', []) if d.get('lang') == 'en'), '')
            score = 'N/A'
            for key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                m = cve.get('metrics', {}).get(key, [])
                if m:
                    score = m[0].get('cvssData', {}).get('baseScore', 'N/A')
                    break
            out.append({'id': cid, 'description': desc, 'score': score,
                        'published': cve.get('published', '')[:10],
                        'url': f"https://nvd.nist.gov/vuln/detail/{cid}"})
        return out
    except Exception as e:
        return [{'id': 'Error', 'description': str(e), 'score': '-', 'published': '-', 'url': '#'}]


# --- Escaneo ------------------------------------------------------------------
def _port_row(p):
    parts = p.split()
    port = html.escape(parts[0])
    service = html.escape(parts[2]) if len(parts) > 2 else ''
    version = html.escape(' '.join(parts[3:])[:55])
    return (f"<tr><td style='color:#00ff88'>{port}</td><td>{service}</td>"
            f"<td style='color:#555;font-size:11px'>{version}</td></tr>")


def run_scan(scan_id, target, ports, intensity):
    scans[scan_id].update({'status': 'running', 'output': [], 'target': target})
    db_insert(scan_id, target, ports, intensity)
    raw_file = DATA_DIR / f"raw_{scan_id}.txt"
    report_file = DATA_DIR / f"report_{scan_id}.html"

    def emit(msg):
        scans[scan_id]['output'].append(msg)

    emit(f"[*] Target: {target}")
    emit(f"[*] Puertos: {ports} | Intensidad: {intensity}")
    emit(f"[*] {datetime.datetime.now().strftime('%H:%M:%S')} — Iniciando nmap...")
    timing = INTENSITIES.get(intensity, '-T3')
    vscript = Path('/usr/share/nmap/scripts/vulners.nse')
    if not vscript.exists():
        # Descarga de terceros sin verificacion de hash: ver README (seccion Seguridad).
        emit("[*] Descargando vulners.nse...")
        try:
            vr = req.get("https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse", timeout=10)
            vr.raise_for_status()
            vscript.write_text(vr.text)
            subprocess.run(['nmap', '--script-updatedb'], capture_output=True)
            emit("[+] vulners.nse instalado")
        except Exception:
            emit("[!] No se pudo descargar vulners.nse")
    scripts = "vulners,vuln,banner" if vscript.exists() else "vuln,banner"
    cmd = ['nmap', '-sV', '-sC', '-O', timing, '--script', scripts,
           '--script-args', 'vulners.showall=true', '-p', ports, target, '-oN', str(raw_file)]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                emit(line)
        proc.wait()
    except Exception as e:
        emit(f"[!!] Error: {e}")
        scans[scan_id]['status'] = 'error'
        db_update(scan_id, 'error', 0, 0, 0, '', 'ERROR', '', '\n'.join(scans[scan_id]['output']))
        return
    emit("\n[*] Generando reporte...")
    raw = raw_file.read_text() if raw_file.exists() else ""
    open_ports = re.findall(r'^(\d+/tcp\s+open\s+\S+.*)', raw, re.MULTILINE)
    cves_found = sorted(set(re.findall(r'CVE-\d{4}-\d+', raw)))
    os_det = next(iter(re.findall(r'OS details: (.+)', raw)), 'No detectado')
    hostname = next(iter(re.findall(r'Nmap scan report for (.+)', raw)), target)
    vuln_count = len(cves_found)
    port_count = len(open_ports)
    warn_flags = []
    checks = [
        (r'message_signing: disabled', 'SMB Signing deshabilitado'),
        (r'23/tcp.*open', 'Telnet expuesto'), (r'3389/tcp.*open', 'RDP expuesto'),
        (r'5900/tcp.*open', 'VNC expuesto'), (r'6379/tcp.*open', 'Redis sin auth'),
        (r'anonymous.*login', 'FTP anonimo'), (r'21/tcp.*open', 'FTP activo'),
    ]
    for pattern, msg in checks:
        if re.search(pattern, raw, re.I):
            warn_flags.append(msg)
    if re.search(r'80/tcp.*open', raw) and not re.search(r'443/tcp.*open', raw):
        warn_flags.append('HTTP sin TLS')
    status = 'VULN' if vuln_count > 0 or re.search(r'VULNERABLE', raw) else ('WARN' if warn_flags else 'CLEAN')
    sc = {'VULN': '#ef4444', 'WARN': '#f59e0b', 'CLEAN': '#00ff88'}[status]
    port_rows = ''.join(_port_row(p) for p in open_ports) or \
        "<tr><td colspan='3' style='color:#444;text-align:center'>Sin puertos</td></tr>"
    cve_rows = ''.join("<tr><td style='color:#60a5fa'>{}</td><td><a href='https://nvd.nist.gov/vuln/detail/{}' target='_blank' style='color:#3a5a8a'>NVD</a></td></tr>".format(
        html.escape(c), html.escape(c)) for c in cves_found) or \
        "<tr><td colspan='2' style='color:#444;text-align:center'>Sin CVEs</td></tr>"
    warn_items = ''.join("<li>&#9888; {}</li>".format(w) for w in warn_flags) or \
        "<li style='color:#444'>Sin advertencias</li>"
    html_report = """<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8"><title>VULNSCAN - {target}</title>
<style>*{{box-sizing:border-box;margin:0;padding:0}}body{{background:#0a0d0a;color:#c8d8c8;font-family:'Segoe UI',sans-serif}}
.hdr{{background:#0d110d;border-bottom:1px solid #1a2a1a;padding:20px 36px;display:flex;justify-content:space-between}}
.logo{{font-size:24px;font-weight:700;letter-spacing:4px}}.logo span{{color:#00ff88}}
.meta{{text-align:right;font-family:monospace;font-size:11px;color:#3a6a3a;line-height:1.8}}.meta b{{color:#00cc66}}
.stats{{display:grid;grid-template-columns:repeat(4,1fr);border-bottom:1px solid #1a2a1a}}
.st{{padding:22px;text-align:center;border-right:1px solid #1a2a1a}}.st:last-child{{border-right:none}}
.stn{{font-size:44px;font-weight:700;font-family:monospace}}.stl{{font-size:9px;letter-spacing:3px;color:#3a5a3a;margin-top:6px}}
.body{{padding:28px 36px;max-width:1100px;margin:0 auto}}
.badge{{display:inline-block;padding:3px 14px;border:1px solid {sc};color:{sc};font-family:monospace;font-size:11px;letter-spacing:2px;margin-bottom:10px}}
.sl2{{font-size:9px;letter-spacing:3px;color:#2a5a2a;border-bottom:1px solid #1a2a1a;padding-bottom:5px;margin:20px 0 10px;font-family:monospace}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:18px}}
table{{width:100%;border-collapse:collapse;font-family:monospace;font-size:12px}}
th{{color:#2a5a2a;font-size:9px;letter-spacing:2px;padding:5px 8px;text-align:left}}
td{{padding:5px 8px;border-bottom:1px solid #111811;color:#8a9a8a}}
ul.wl{{list-style:none;font-family:monospace;font-size:12px}}ul.wl li{{padding:4px 0;color:#f59e0b}}
.raw{{background:#060906;border:1px solid #1a2a1a;padding:14px;font-family:monospace;font-size:10px;color:#4a7a4a;white-space:pre-wrap;overflow:auto;max-height:380px}}
.ftr{{border-top:1px solid #1a2a1a;padding:14px 36px;display:flex;justify-content:space-between;font-family:monospace;font-size:10px;color:#2a4a2a;margin-top:40px}}
</style></head><body>
<div class="hdr"><div><div class="logo">VULN<span>SCAN</span></div></div>
<div class="meta">Generated: <b>{date}</b><br>Target: <b>{target}</b><br>Host: <b>{hostname}</b></div></div>
<div class="stats">
<div class="st"><div class="stn" style="color:#00ff88">1</div><div class="stl">HOSTS</div></div>
<div class="st"><div class="stn" style="color:#f59e0b">{port_count}</div><div class="stl">PUERTOS</div></div>
<div class="st"><div class="stn" style="color:#ef4444">{vuln_count}</div><div class="stl">CVEs</div></div>
<div class="st"><div class="stn" style="color:{sc}">{warn_count}</div><div class="stl">WARNINGS</div></div>
</div>
<div class="body"><div class="badge">{status}</div>
<p style="color:#555;font-family:monospace;font-size:11px;margin-bottom:4px">OS: {os_det}</p>
<div class="grid">
<div><div class="sl2">// PUERTOS</div>
<table><thead><tr><th>Puerto</th><th>Servicio</th><th>Version</th></tr></thead><tbody>{port_rows}</tbody></table>
<div class="sl2" style="margin-top:18px">// ADVERTENCIAS</div><ul class="wl">{warn_items}</ul></div>
<div><div class="sl2">// CVEs</div>
<table><thead><tr><th>CVE ID</th><th>Ref</th></tr></thead><tbody>{cve_rows}</tbody></table></div>
</div>
<div class="sl2" style="margin-top:24px">// OUTPUT NMAP</div>
<div class="raw">{raw_escaped}</div></div>
<div class="ftr"><span>VULNSCAN</span><span>{fname}</span></div>
</body></html>""".format(
        target=html.escape(target), sc=sc, status=status,
        date=datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
        hostname=html.escape(hostname), port_count=port_count, vuln_count=vuln_count,
        warn_count=len(warn_flags), os_det=html.escape(os_det), port_rows=port_rows,
        cve_rows=cve_rows, warn_items=warn_items,
        raw_escaped=html.escape(raw[:10000]),
        fname=html.escape(report_file.name))
    report_file.write_text(html_report)
    db_update(scan_id, 'done', vuln_count, port_count, len(warn_flags), os_det[:100], status,
              str(report_file), raw[:50000])
    scans[scan_id].update({'status': 'done', 'report_path': str(report_file),
                           'summary': {'target': target, 'ports': port_count, 'cves': vuln_count,
                                       'status': status, 'os': os_det[:35],
                                       'date': datetime.datetime.now().strftime('%d/%m/%Y %H:%M')}})
    emit(f"[+] Reporte: {report_file.name}")
    emit(f"[+] CVEs: {vuln_count} | Puertos: {port_count} | {status}")
    emit(f"[+] Guardado en DB: {DB_PATH}")


# --- Frontend -----------------------------------------------------------------
APP_JS = """
var sid=null,poll=null;
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
setInterval(function(){var el=document.getElementById('clk');if(el)el.textContent=new Date().toLocaleString('es-AR');},1000);
function sw(name){['dashboard','cves','reports'].forEach(function(n){
    document.getElementById('t-'+n).classList.toggle('active',n===name);
    document.getElementById('tc-'+n).classList.toggle('active',n===name);
    document.getElementById('n-'+n).classList.toggle('act',n===name);});
    if(name==='cves')loadCVEs();if(name==='reports')loadReports();}
function startScan(){
    var target=document.getElementById('target').value.trim();
    if(!target){alert('Ingresa un target');return;}
    var ports=document.getElementById('ports').value;
    var intensity=document.getElementById('intensity').value;
    var btn=document.getElementById('sbtn');
    btn.disabled=true;btn.textContent='ESCANEANDO...';
    document.getElementById('term').textContent='';
    fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({target:target,ports:ports,intensity:intensity})})
    .then(function(r){return r.json();})
    .then(function(d){if(d.error){throw new Error(d.error);}sid=d.scan_id;pollScan();})
    .catch(function(e){alert('Error: '+e.message);btn.disabled=false;btn.textContent='INICIAR SCAN';});}
function pollScan(){
    var term=document.getElementById('term');
    poll=setInterval(function(){
        fetch('/api/scan/'+sid).then(function(r){return r.json();}).then(function(d){
            term.textContent=d.output.join('\\n');term.scrollTop=term.scrollHeight;
            if(d.status==='done'||d.status==='error'){
                clearInterval(poll);
                var btn=document.getElementById('sbtn');
                btn.disabled=false;btn.textContent='INICIAR SCAN';
                loadDash();loadReports();}});},1200);}
function loadCVEs(){
    document.getElementById('cvelist').innerHTML='<div class="empty">Cargando CVEs...</div>';
    fetch('/api/cves').then(function(r){return r.json();}).then(function(cves){
        var html='';
        cves.forEach(function(c){
            html+='<div class="ccard"><div><span class="cid">'+esc(c.id)+'</span><span class="cscore">CVSS '+esc(c.score)+'</span></div>';
            html+='<div class="cdesc">'+esc(c.description)+'</div>';
            html+='<div class="cdate">'+esc(c.published)+' &middot; <a href="'+esc(c.url)+'" target="_blank" style="color:#2a5a2a">NVD</a></div></div>';});
        document.getElementById('cvelist').innerHTML=html||'<div class="empty">Sin datos</div>';});}
function buildCard(r,showOs){
    var st=esc(r.status||'');
    var sc=esc((r.status||'').toLowerCase());
    var html='<div class="rcard '+sc+'">';
    html+='<div><div class="rip">'+esc(r.target)+'</div>';
    html+='<div class="rmeta">'+esc(r.date)+' &middot; '+esc(r.ports)+' puertos &middot; '+esc(r.cves)+' CVEs';
    if(showOs&&r.os)html+=' &middot; '+esc(r.os);
    html+='</div></div><div style="display:flex;align-items:center;gap:6px">';
    html+='<span class="bs b'+st+'">'+st+'</span>';
    html+='<a href="/api/reports/'+encodeURIComponent(r.id)+'/download"><button class="dlb">HTML</button></a>';
    html+='</div></div>';return html;}
function loadReports(){
    fetch('/api/reports').then(function(r){return r.json();}).then(function(rs){
        var html='';rs.forEach(function(r){html+=buildCard(r,true);});
        document.getElementById('rlist').innerHTML=html||'<div class="empty">Sin reportes.</div>';});}
function loadDash(){
    fetch('/api/reports').then(function(r){return r.json();}).then(function(rs){
        document.getElementById('ts').textContent=rs.length;
        document.getElementById('tv').textContent=rs.reduce(function(a,r){return a+(r.cves||0);},0);
        var h={};rs.forEach(function(r){h[r.target]=1;});
        document.getElementById('th').textContent=Object.keys(h).length;
        var html='';rs.slice(0,6).forEach(function(r){html+=buildCard(r,false);});
        document.getElementById('recent').innerHTML=html||'<div class="empty">Sin scans.</div>';});}
document.addEventListener('DOMContentLoaded',function(){loadDash();});
"""

HTML_UI = """<!DOCTYPE html><html lang="es"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VULNSCAN WEB</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0a0d0a;color:#c8d8c8;font-family:'Segoe UI',sans-serif;min-height:100vh;overflow:hidden}
.hdr{background:#0d110d;border-bottom:1px solid #1a2a1a;padding:14px 28px;display:flex;justify-content:space-between;align-items:center;height:54px}
.logo{font-size:20px;font-weight:700;letter-spacing:4px}.logo span{color:#00ff88}
.sub{font-size:8px;color:#3a5a3a;letter-spacing:3px;font-family:monospace;margin-top:2px}
.nav{display:flex;gap:20px;font-family:monospace;font-size:10px;letter-spacing:2px}
.nav a{color:#3a6a3a;cursor:pointer}.nav a:hover,.nav a.act{color:#00ff88}
.layout{display:grid;grid-template-columns:340px 1fr;height:calc(100vh - 90px)}
.side{background:#0d110d;border-right:1px solid #1a2a1a;padding:18px;overflow-y:auto}
.cont{padding:20px;overflow-y:auto}
.slabel{font-size:8px;letter-spacing:3px;color:#2a5a2a;margin-bottom:12px;font-family:monospace;border-bottom:1px solid #1a2a1a;padding-bottom:5px}
.fg{margin-bottom:12px}.fg label{display:block;font-size:9px;letter-spacing:2px;color:#3a6a3a;margin-bottom:5px;font-family:monospace}
.fg input,.fg select{width:100%;background:#060906;border:1px solid #1a2a1a;color:#c8d8c8;padding:7px 10px;font-family:monospace;font-size:11px;outline:none}
.fg input:focus,.fg select:focus{border-color:#00ff88}
.btn{width:100%;background:transparent;border:1px solid #00ff88;color:#00ff88;padding:9px;font-family:monospace;font-size:11px;letter-spacing:3px;cursor:pointer}
.btn:hover{background:#00ff88;color:#0a0d0a}.btn:disabled{border-color:#2a5a2a;color:#2a5a2a;cursor:not-allowed;background:transparent}
.term{background:#060906;border:1px solid #1a2a1a;padding:10px;font-family:monospace;font-size:10px;color:#4a8a4a;height:200px;overflow-y:auto;white-space:pre-wrap;margin-top:12px}
.tabs{display:flex;border-bottom:1px solid #1a2a1a;margin-bottom:16px}
.tab{padding:7px 18px;font-family:monospace;font-size:9px;letter-spacing:2px;color:#3a5a3a;cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px}
.tab.active{color:#00ff88;border-bottom-color:#00ff88}
.tc{display:none}.tc.active{display:block}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:14px}
.s{background:#060906;border:1px solid #1a2a1a;padding:10px;text-align:center}
.sn{font-size:26px;font-weight:700;font-family:monospace}.sl{font-size:8px;letter-spacing:2px;color:#3a5a3a;margin-top:3px}
.ccard{background:#0d110d;border:1px solid #1a2a1a;border-left:3px solid #ef4444;padding:10px 14px;margin-bottom:5px}
.cid{font-family:monospace;font-size:12px;font-weight:700;color:#ef4444}
.cscore{font-family:monospace;font-size:10px;color:#f59e0b;float:right}
.cdesc{font-size:11px;color:#5a7a5a;margin-top:3px;line-height:1.3}
.cdate{font-size:9px;color:#2a4a2a;margin-top:3px;font-family:monospace}
.rcard{background:#0d110d;border:1px solid #1a2a1a;border-left:3px solid #00ff88;padding:10px 14px;margin-bottom:5px;display:flex;justify-content:space-between;align-items:center}
.rcard.vuln{border-left-color:#ef4444}.rcard.warn{border-left-color:#f59e0b}
.rip{font-family:monospace;font-size:13px;color:#e8f8e8}
.rmeta{font-family:monospace;font-size:9px;color:#3a6a3a;margin-top:2px}
.bs{font-family:monospace;font-size:9px;padding:2px 8px;letter-spacing:2px}
.bCLEAN{color:#00ff88;border:1px solid #00ff88}.bVULN{color:#ef4444;border:1px solid #ef4444}.bWARN{color:#f59e0b;border:1px solid #f59e0b}
.dlb{color:#2a5a2a;font-family:monospace;font-size:9px;border:1px solid #1a2a1a;padding:3px 8px;cursor:pointer;background:transparent;margin-left:6px}
.dlb:hover{color:#00ff88;border-color:#00ff88}
.empty{color:#2a5a2a;font-family:monospace;font-size:11px;text-align:center;padding:30px}
.ftr{border-top:1px solid #1a2a1a;padding:10px 28px;font-family:monospace;font-size:9px;color:#2a4a2a;display:flex;justify-content:space-between;height:36px;align-items:center}
</style></head><body>
<div class="hdr">
  <div><div class="logo">VULN<span>SCAN</span> WEB</div><div class="sub">SECURITY ASSESSMENT PLATFORM</div></div>
  <div class="nav">
    <a onclick="sw('dashboard')" id="n-dashboard" class="act">DASHBOARD</a>
    <a onclick="sw('cves')" id="n-cves">CVE FEED</a>
    <a onclick="sw('reports')" id="n-reports">REPORTES</a>
  </div>
</div>
<div class="layout">
  <div class="side">
    <div class="slabel">// NUEVO SCAN</div>
    <div class="fg"><label>TARGET</label><input type="text" id="target" placeholder="192.168.1.1"></div>
    <div class="fg"><label>PUERTOS</label>
      <select id="ports">
        <option value="21,22,23,25,53,80,135,139,443,445,1433,3306,3389,5432,5900,5985,6379,8080,8443,9200,27017">Criticos</option>
        <option value="1-1024">Well-known (1-1024)</option>
        <option value="80,443,8080,8443">Solo web</option>
        <option value="22,3389,5985,5900">Solo acceso remoto</option>
        <option value="1-65535">Todos (lento)</option>
      </select></div>
    <div class="fg"><label>INTENSIDAD</label>
      <select id="intensity">
        <option value="rapido">Rapido (T4)</option>
        <option value="normal" selected>Normal (T3)</option>
        <option value="sigiloso">Sigiloso (T1)</option>
      </select></div>
    <button class="btn" id="sbtn" onclick="startScan()">INICIAR SCAN</button>
    <div class="term" id="term">[*] Sistema listo. Ingresa un target.</div>
  </div>
  <div class="cont">
    <div class="tabs">
      <div class="tab active" id="t-dashboard" onclick="sw('dashboard')">DASHBOARD</div>
      <div class="tab" id="t-cves" onclick="sw('cves')">CVE FEED</div>
      <div class="tab" id="t-reports" onclick="sw('reports')">HISTORIAL</div>
    </div>
    <div class="tc active" id="tc-dashboard">
      <div class="stats">
        <div class="s"><div class="sn" style="color:#00ff88" id="ts">0</div><div class="sl">SCANS</div></div>
        <div class="s"><div class="sn" style="color:#ef4444" id="tv">0</div><div class="sl">CVEs</div></div>
        <div class="s"><div class="sn" style="color:#f59e0b" id="th">0</div><div class="sl">HOSTS</div></div>
      </div>
      <div class="slabel">// RECIENTES</div>
      <div id="recent"><div class="empty">Sin scans.</div></div>
    </div>
    <div class="tc" id="tc-cves">
      <div class="slabel">// CVEs CRITICOS - NVD NIST</div>
      <div id="cvelist"><div class="empty">Click en CVE FEED.</div></div>
    </div>
    <div class="tc" id="tc-reports">
      <div class="slabel">// HISTORIAL COMPLETO</div>
      <div id="rlist"><div class="empty">Sin reportes.</div></div>
    </div>
  </div>
</div>
<div class="ftr"><span>VULNSCAN WEB</span><span id="clk"></span></div>
<script src="/js/app.js"></script>
</body></html>"""


@app.route('/')
def index():
    return HTML_UI


@app.route('/js/app.js')
def serve_js():
    return Response(APP_JS, mimetype='application/javascript')


# --- API ----------------------------------------------------------------------
@app.route('/api/scan', methods=['POST'])
def api_scan():
    d = request.get_json(silent=True) or {}
    target = validate_target(d.get('target'))
    ports = validate_ports(d.get('ports', '80,443'))
    intensity = d.get('intensity', 'normal')
    if target is None:
        return jsonify({'error': 'Target invalido. Usa IP, rango CIDR o hostname.'}), 400
    if ports is None:
        return jsonify({'error': 'Puertos invalidos.'}), 400
    if intensity not in INTENSITIES:
        intensity = 'normal'
    scan_id = str(uuid.uuid4())[:8]
    scans[scan_id] = {'status': 'starting', 'output': [], 'target': target}
    threading.Thread(target=run_scan, args=(scan_id, target, ports, intensity), daemon=True).start()
    return jsonify({'scan_id': scan_id})


@app.route('/api/scan/<scan_id>')
def api_scan_status(scan_id):
    s = scans.get(scan_id, {})
    return jsonify({'status': s.get('status', 'unknown'), 'output': s.get('output', []),
                    'summary': s.get('summary', {})})


@app.route('/api/cves')
def api_cves():
    return jsonify(get_latest_cves(12))


@app.route('/api/reports')
def api_reports():
    result = []
    for k, v in reversed(list(scans.items())):
        if v.get('status') == 'done' and v.get('summary'):
            s = v['summary']
            result.append({'id': k, 'target': s.get('target', ''), 'ports': s.get('ports', 0),
                           'cves': s.get('cves', 0), 'status': s.get('status', 'CLEAN'),
                           'os': s.get('os', '')[:30], 'date': s.get('date', '')})
    return jsonify(result)


@app.route('/api/reports/<scan_id>/download')
def api_download(scan_id):
    s = scans.get(scan_id, {})
    p = s.get('report_path')
    if p and Path(p).exists():
        safe = re.sub(r'[^A-Za-z0-9._-]', '_', s.get('target', 'host'))
        return send_file(p, as_attachment=True, download_name=f"vulnscan_{safe}.html")
    return "No encontrado", 404


@app.route('/api/db/stats')
def api_db_stats():
    rows = db_get_all()
    return jsonify({'total_scans': len(rows), 'total_cves': sum(r['cve_count'] for r in rows),
                    'unique_hosts': len(set(r['target'] for r in rows))})


if __name__ == '__main__':
    load_scans_from_db()
    print("\n  EASY VULNSCANNER")
    print(f"  DB: {DB_PATH}")
    print(f"  http://{HOST}:{PORT}\n")
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
