"""
BankShield CVE Engine — Serveur complet avec polling NVD
=========================================================
- Polling périodique (toutes les 15 min) des CVE des dernières 24h
- Stocke TOUTES les CVE avec un flag "matched"
- Enrichit et dispatch uniquement les CVE matchées
- Dashboard avec filtre "Matchées uniquement"
"""

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import threading
import time
import uuid
import requests
import os
import logging
from datetime import datetime, timezone, timedelta

logging.basicConfig(level=logging.INFO, format="%(asctime)s [SERVER] %(message)s")
app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)

# ─────────────────────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────────────────────
NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
AGENT_URL = os.getenv("AGENT_URL", "http://localhost:5001")
SERVER_URL = os.getenv("SERVER_URL", "http://10.10.30.10:5000")
POLL_INTERVAL_MINUTES = int(os.getenv("POLL_INTERVAL_MINUTES", "15"))
REQUEST_TIMEOUT = 15
AGENT_DISPATCH_TIMEOUT = 8
NVD_RATE_LIMIT_DELAY = 0.7 if NVD_API_KEY else 6.0

# ─────────────────────────────────────────────────────────
#  INVENTAIRE INFRASTRUCTURE BANCAIRE
# ─────────────────────────────────────────────────────────
HOSTS = {
    "srv-web-01": {
        "name": "Serveur Web Principal",
        "host": "10.10.10.10",
        "os": "Ubuntu 22.04 LTS",
        "agent": "http://10.10.10.10:5001",
        "cpe": ["apache:http_server", "nginx:nginx", "openssl:openssl", "php:php"],
        "packages": ["apache2", "nginx", "openssl", "php"],
        "tags": ["web", "dmz"],
        "criticality": 7,
        "exposure": 10,
    },
    "srv-db-01": {
        "name": "Base de données",
        "host": "10.10.40.10",
        "os": "Ubuntu 22.04 LTS",
        "agent": "http://10.10.40.10:5001",
        "cpe": ["postgresql:postgresql", "mysql:mysql"],
        "packages": ["postgresql-14", "mysql-server"],
        "tags": ["database", "internal"],
        "criticality": 9,
        "exposure": 5,
    },
    "srv-soc-01": {
        "name": "SOC / Monitoring",
        "host": "10.10.30.10",
        "os": "Ubuntu 22.04 LTS",
        "agent": "http://10.10.30.10:5001",
        "cpe": ["elastic:elasticsearch", "grafana:grafana"],
        "packages": ["elasticsearch", "grafana"],
        "tags": ["soc", "monitoring"],
        "criticality": 8,
        "exposure": 3,
    }
}

# ─────────────────────────────────────────────────────────
#  STOCKAGE & CACHE
# ─────────────────────────────────────────────────────────
cve_store = {}
job_store = {}
test_log = []
lock = threading.Lock()
_last_poll = None
cache_kev = {"data": None, "expires": 0}
cache_mitre = {}
last_nvd_request_time = 0
requests_session = requests.Session()

# ─────────────────────────────────────────────────────────
#  FONCTIONS UTILITAIRES
# ─────────────────────────────────────────────────────────
def now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def now_hm():
    return datetime.now(timezone.utc).strftime("%H:%M:%S")

def add_test_log(level, msg):
    entry = {"ts": now_iso(), "level": level, "msg": msg}
    with lock:
        test_log.append(entry)
        if len(test_log) > 200:
            test_log.pop(0)
    logging.info(f"[{level.upper()}] {msg}")

def respect_nvd_rate_limit():
    global last_nvd_request_time
    elapsed = time.time() - last_nvd_request_time
    if elapsed < NVD_RATE_LIMIT_DELAY:
        time.sleep(NVD_RATE_LIMIT_DELAY - elapsed)
    last_nvd_request_time = time.time()

def to_aware(dt_str):
    if not dt_str:
        return None
    try:
        s = dt_str.strip()
        if s.endswith('Z'):
            s = s[:-1] + '+00:00'
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None

# ─────────────────────────────────────────────────────────
#  PARSING NVD
# ─────────────────────────────────────────────────────────
def parse_nvd_cve(cve_raw: dict) -> dict:
    cve_id = cve_raw.get("id", "")
    desc = ""
    for d in cve_raw.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break

    score, sev, vector = 0.0, "UNKNOWN", ""
    metrics = cve_raw.get("metrics", {})
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            cd = m.get("cvssData", {})
            score = float(cd.get("baseScore", 0.0))
            sev = cd.get("baseSeverity", "")
            vector = cd.get("vectorString", "")
            if not sev:
                sev = m.get("baseSeverity", "")
            if not sev:
                sev = "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
            break

    cpes = []
    for cfg in cve_raw.get("configurations", []):
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                uri = match.get("criteria", "")
                if uri:
                    cpes.append(uri.lower())

    cwes = []
    for w in cve_raw.get("weaknesses", []):
        for d in w.get("description", []):
            if d.get("value", "").startswith("CWE-"):
                cwes.append(d["value"])

    refs = [r.get("url", "") for r in cve_raw.get("references", [])[:5]]

    pub_dt = to_aware(cve_raw.get("published", ""))
    published_iso = pub_dt.isoformat() if pub_dt else now_iso()
    mod_dt = to_aware(cve_raw.get("lastModified", ""))
    modified_iso = mod_dt.isoformat() if mod_dt else now_iso()

    return {
        "id": cve_id,
        "description": desc,
        "score": score,
        "severity": sev.upper(),
        "vector": vector,
        "cpes": cpes,
        "cwes": cwes,
        "references": refs,
        "published": published_iso,
        "modified": modified_iso,
        "source": "NVD",
    }

def fetch_single_cve(cve_id: str):
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    params = {"cveId": cve_id}
    respect_nvd_rate_limit()
    try:
        resp = requests_session.get(NVD_BASE, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            return None
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None
        return parse_nvd_cve(vulns[0].get("cve", {}))
    except Exception:
        return None

# ─────────────────────────────────────────────────────────
#  ENRICHISSEMENT (KEV, EPSS, MITRE)
# ─────────────────────────────────────────────────────────
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"

def get_kev_status(cve_id):
    now_ts = time.time()
    if cache_kev["expires"] < now_ts:
        try:
            resp = requests_session.get(CISA_KEV_URL, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            cache_kev["data"] = {item["cveID"]: item for item in data.get("vulnerabilities", [])}
            cache_kev["expires"] = now_ts + 3600
        except Exception:
            cache_kev["data"] = {}
            cache_kev["expires"] = now_ts + 7200
    cve_info = cache_kev["data"].get(cve_id)
    return {"in_kev": cve_info is not None, "kev_date_added": cve_info.get("dateAdded") if cve_info else None}

def get_epss_score(cve_id):
    try:
        resp = requests_session.get(EPSS_API_URL, params={"cve": cve_id}, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        for item in data.get("data", []):
            if item.get("cve") == cve_id:
                return {"score": float(item.get("epss", 0.0)), "percentile": float(item.get("percentile", 0.0)), "date": item.get("date")}
        return {"score": 0.0, "percentile": 0.0, "date": None}
    except Exception:
        return {"score": 0.0, "percentile": 0.0, "date": None}

def get_mitre_attck(cve_id: str) -> dict:
    with lock:
        if cve_id in cache_mitre:
            return cache_mitre[cve_id]
    try:
        resp = requests_session.get(f"https://cve.circl.lu/api/cve/{cve_id}", timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            attack_info = {"tactics": [], "techniques": [], "capec_ids": data.get("capec", [])}
            for ref in data.get("references", []):
                if "attack.mitre.org" in ref:
                    parts = ref.rstrip('/').split('/')
                    if len(parts) >= 2:
                        tech = parts[-1]
                        if tech.startswith('T'):
                            attack_info["techniques"].append(tech)
            attack_info["techniques"] = list(set(attack_info["techniques"]))
            with lock:
                cache_mitre[cve_id] = attack_info
            return attack_info
    except Exception:
        pass
    return {"tactics": [], "techniques": [], "capec_ids": []}

def enrich_cve(cve_data: dict) -> dict:
    cve_id = cve_data["id"]
    kev = get_kev_status(cve_id)
    epss = get_epss_score(cve_id)
    mitre = get_mitre_attck(cve_id)
    cve_data["kev_status"] = kev["in_kev"]
    cve_data["kev_date"] = kev["kev_date_added"]
    cve_data["epss_score"] = epss["score"]
    cve_data["epss_percentile"] = epss["percentile"]
    cve_data["epss_date"] = epss.get("date")
    cve_data["mitre_attck"] = mitre
    cve_data["exploit_available"] = False
    return cve_data

# ─────────────────────────────────────────────────────────
#  MATCHING INFRASTRUCTURE
# ─────────────────────────────────────────────────────────
def _quick_match_infra(cve: dict) -> bool:
    """Vérifie rapidement si la CVE peut concerner l'infrastructure (CPE ou mots-clés)."""
    cve_cpes = cve.get("cpes", [])
    cve_desc = cve.get("description", "").lower()
    for host in HOSTS.values():
        for host_cpe in host.get("cpe", []):
            vendor, product = (host_cpe.split(":", 1) + ["", ""])[:2]
            for nvd_cpe in cve_cpes:
                parts = nvd_cpe.split(":")
                if len(parts) >= 5:
                    nvd_vendor = parts[3]
                    nvd_product = parts[4]
                    if vendor == nvd_vendor and (not product or product == nvd_product):
                        return True
    keywords = set()
    for host in HOSTS.values():
        for kw in host.get("packages", []) + host.get("tags", []):
            if len(kw) > 3:
                keywords.add(kw.lower())
    return any(kw in cve_desc for kw in keywords)

def match_hosts(cve: dict) -> list:
    """Retourne la liste des hôtes affectés (détail complet)."""
    cve_cpes = cve.get("cpes", [])
    cve_desc = cve.get("description", "").lower()
    affected = []
    for host_id, host in HOSTS.items():
        matched = False
        for host_cpe in host.get("cpe", []):
            vendor, product = (host_cpe.split(":", 1) + ["", ""])[:2]
            for nvd_cpe in cve_cpes:
                parts = nvd_cpe.split(":")
                if len(parts) >= 5:
                    nvd_vendor = parts[3]
                    nvd_product = parts[4]
                    if vendor == nvd_vendor and (not product or product == nvd_product):
                        matched = True
                        break
            if matched:
                break
        if not matched:
            keywords = set()
            for cpe in host.get("cpe", []):
                keywords.update(cpe.replace("_", " ").replace(":", " ").split())
            for pkg in host.get("packages", []):
                keywords.add(pkg.lower())
            keywords.update(host.get("tags", []))
            keywords = {kw for kw in keywords if len(kw) > 3}
            if any(kw in cve_desc for kw in keywords):
                matched = True
        if matched:
            affected.append(host_id)
    return affected

def compute_bsrs(cve, host):
    cvss = cve.get("score", 0.0) / 10.0
    epss = cve.get("epss_score", 0.0)
    kev_bonus = 0.20 if cve.get("kev_status", False) else 0.0
    host_crit = host.get("criticality", 5) / 10.0
    host_exp = host.get("exposure", 5) / 10.0
    bsrs_raw = (cvss * 0.25) + (epss * 0.20) + kev_bonus + (host_crit * 0.20) + (host_exp * 0.10)
    bsrs = round(bsrs_raw * 100, 1)
    if bsrs >= 80:
        priority = "P1-IMMEDIATE"
    elif bsrs >= 60:
        priority = "P2-URGENT"
    elif bsrs >= 40:
        priority = "P3-STANDARD"
    else:
        priority = "P4-INFO"
    return bsrs, priority

def run_full_pipeline(cve: dict, source_label: str = "INJECT") -> dict:
    """Exécute tout le pipeline pour une CVE (enrichissement, match, dispatch)."""
    cve_id = cve["id"]
    add_test_log("info", f"Pipeline start: {cve_id} [{source_label}]")
    cve = enrich_cve(cve)
    affected_hosts = match_hosts(cve)
    affected_details = []
    for host_id in affected_hosts:
        host = HOSTS[host_id]
        bsrs, priority = compute_bsrs(cve, host)
        affected_details.append({
            "host_id": host_id,
            "host_name": host["name"],
            "bsrs": bsrs,
            "priority": priority,
        })
    cve["affected_hosts"] = affected_hosts
    cve["affected_details"] = affected_details
    cve["status"] = "new"
    cve["detected_at"] = now_iso()
    cve["inject_source"] = source_label
    with lock:
        cve_store[cve_id] = cve
    avg_bsrs = round(sum(d["bsrs"] for d in affected_details) / len(affected_details), 1) if affected_details else 0
    add_test_log("info", f"CVE {cve_id} [{cve['severity']}] avg BSRS={avg_bsrs}, hosts={len(affected_hosts)}")
    dispatched_jobs = []
    for aff in affected_details:
        if aff["priority"] in ("P1-IMMEDIATE", "P2-URGENT"):
            host = HOSTS[aff["host_id"]]
            job_id = str(uuid.uuid4())[:8].upper()
            job = {
                "job_id": job_id,
                "cve_id": cve_id,
                "severity": cve["severity"],
                "score": cve["score"],
                "bsrs": aff["bsrs"],
                "priority": aff["priority"],
                "host_id": aff["host_id"],
                "host_name": host["name"],
                "host_ip": host["host"],
                "host_os": host["os"],
                "status": "queued",
                "auto": True,
                "source": source_label,
                "created_at": now_iso(),
                "updated_at": now_iso(),
                "log": [f"[{now_hm()}] Auto job created"],
            }
            with lock:
                job_store[job_id] = job
            threading.Thread(target=_dispatch_to_agent, args=(job_id, cve, host), daemon=True).start()
            dispatched_jobs.append(job_id)
            add_test_log("info", f"Dispatched job {job_id} to {host['name']}")
    return {
        "cve_id": cve_id,
        "severity": cve["severity"],
        "score": cve["score"],
        "bsrs_avg": avg_bsrs,
        "affected_hosts": affected_hosts,
        "affected_details": affected_details,
        "jobs_created": dispatched_jobs,
        "auto_dispatched": len(dispatched_jobs) > 0,
    }

def _dispatch_to_agent(job_id: str, cve: dict, host: dict):
    payload = {
        "job_id": job_id,
        "cve_id": cve["id"],
        "severity": cve["severity"],
        "score": cve["score"],
        "description": cve.get("description", ""),
        "host_os": host["os"],
        "packages": host.get("packages", []),
        "callback_url": f"{SERVER_URL}/api/agent/callback",
    }
    agent_url = host.get("agent", AGENT_URL)
    with lock:
        if job_id in job_store:
            job_store[job_id]["status"] = "dispatched"
            job_store[job_id]["log"].append(f"[{now_hm()}] Dispatching to {agent_url}")
    try:
        resp = requests_session.post(f"{agent_url}/execute", json=payload, timeout=AGENT_DISPATCH_TIMEOUT)
        if resp.status_code == 200:
            add_test_log("success", f"Job {job_id} accepted by agent")
            with lock:
                if job_id in job_store:
                    job_store[job_id]["status"] = "running"
        else:
            raise Exception(f"HTTP {resp.status_code}")
    except Exception as e:
        error_msg = f"Agent unreachable: {e}"
        with lock:
            if job_id in job_store:
                job_store[job_id]["status"] = "failed"
                job_store[job_id]["log"].append(f"[{now_hm()}] {error_msg}")
        add_test_log("error", error_msg)

# ─────────────────────────────────────────────────────────
#  POLLING NVD (stocke TOUTES les CVE)
# ─────────────────────────────────────────────────────────
def poll_nvd_feed(hours_back=24):
    """Récupère les CVE des dernières X heures, stocke TOUTES, exécute pipeline seulement si match."""
    global _last_poll
    _last_poll = now_iso()
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours_back)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 2000
    }
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    all_cves = []
    start_index = 0
    add_test_log("info", f"NVD poll: fetching CVEs from last {hours_back}h")
    while True:
        params["startIndex"] = start_index
        respect_nvd_rate_limit()
        try:
            resp = requests_session.get(NVD_BASE, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
            if resp.status_code != 200:
                break
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break
            all_cves.extend(vulns)
            total = data.get("totalResults", 0)
            if start_index + len(vulns) >= total:
                break
            start_index += len(vulns)
        except Exception as e:
            add_test_log("error", f"NVD poll error: {e}")
            break
    add_test_log("info", f"Fetched {len(all_cves)} CVEs")
    imported = 0
    for vuln in all_cves:
        cve_data = parse_nvd_cve(vuln.get("cve", {}))
        if not cve_data:
            continue
        # Vérifier si la CVE match l'infrastructure
        matched = _quick_match_infra(cve_data)
        cve_data["matched"] = matched
        cve_data["status"] = "new" if matched else "ignored"
        cve_data["detected_at"] = now_iso()
        cve_data["inject_source"] = "NVD-POLL"
        with lock:
            if cve_data["id"] in cve_store:
                continue
            cve_store[cve_data["id"]] = cve_data
        if matched:
            # Exécute le pipeline complet (enrichissement + dispatch)
            run_full_pipeline(cve_data, source_label="NVD-POLL")
            imported += 1
        else:
            add_test_log("debug", f"CVE {cve_data['id']} ignorée (pas de match)")
    add_test_log("info", f"NVD poll terminé: {imported} nouvelles CVE matchées")
    return imported

def polling_loop():
    """Boucle de polling périodique."""
    while True:
        poll_nvd_feed(hours_back=24)
        time.sleep(POLL_INTERVAL_MINUTES * 60)

# ─────────────────────────────────────────────────────────
#  SYNCHRO MANUELLE (jour en cours)
# ─────────────────────────────────────────────────────────
def sync_nvd_cves():
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    url = f"{NVD_BASE}?pubStartDate={today_str}T00:00:00.000&pubEndDate={today_str}T23:59:59.999&resultsPerPage=2000"
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    all_cves = []
    start_index = 0
    while True:
        paginated_url = f"{url}&startIndex={start_index}"
        respect_nvd_rate_limit()
        try:
            resp = requests_session.get(paginated_url, headers=headers, timeout=REQUEST_TIMEOUT)
            if resp.status_code != 200:
                break
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break
            all_cves.extend(vulns)
            total = data.get("totalResults", 0)
            if start_index + len(vulns) >= total:
                break
            start_index += len(vulns)
        except Exception:
            break
    imported = 0
    for vuln in all_cves:
        cve_data = parse_nvd_cve(vuln.get("cve", {}))
        if not cve_data:
            continue
        matched = _quick_match_infra(cve_data)
        cve_data["matched"] = matched
        with lock:
            if cve_data["id"] in cve_store:
                continue
            cve_store[cve_data["id"]] = cve_data
        if matched:
            run_full_pipeline(cve_data, source_label="NVD-AUTO-SYNC")
            imported += 1
    return imported

# ─────────────────────────────────────────────────────────
#  API ROUTES
# ─────────────────────────────────────────────────────────
@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.get("/api/warn")
def api_warn():
    with lock:
        items = list(cve_store.values())
    items.sort(key=lambda c: c.get("detected_at", ""), reverse=True)
    summary = {
        "total": len(items),
        "critical": sum(1 for c in items if c.get("severity") == "CRITICAL"),
        "high": sum(1 for c in items if c.get("severity") == "HIGH"),
        "medium": sum(1 for c in items if c.get("severity") == "MEDIUM"),
        "affected": sum(1 for c in items if c.get("matched") is True),
        "patched": sum(1 for c in items if c.get("status") == "patched"),
        "last_poll": _last_poll,
    }
    return jsonify({"ok": True, "summary": summary, "cves": items})

@app.get("/api/jobs")
def api_jobs():
    with lock:
        jobs = sorted(job_store.values(), key=lambda j: j["created_at"], reverse=True)
    return jsonify({"ok": True, "jobs": jobs[:100]})

@app.get("/api/hosts")
def api_hosts():
    with lock:
        cves = list(cve_store.values())
    result = {}
    for hid, h in HOSTS.items():
        active = [c["id"] for c in cves if hid in c.get("affected_hosts", []) and c.get("status") != "patched"]
        status = "critical" if any(c.get("severity") == "CRITICAL" for c in cves if hid in c.get("affected_hosts", [])) else "warning" if active else "ok"
        result[hid] = {**h, "status": status, "active_cves": active, "cve_count": len(active)}
    return jsonify({"ok": True, "hosts": result})

@app.post("/api/auto_fix")
def api_auto_fix():
    body = request.get_json(force=True) or {}
    cve_id = body.get("cve_id")
    if not cve_id:
        return jsonify({"ok": False, "error": "cve_id required"}), 400
    with lock:
        cve = cve_store.get(cve_id)
    if not cve:
        return jsonify({"ok": False, "error": "CVE unknown"}), 404
    affected_details = cve.get("affected_details", [])
    if not affected_details:
        return jsonify({"ok": False, "error": "No affected hosts"}), 400
    job_ids = []
    for aff in affected_details:
        host = HOSTS.get(aff["host_id"])
        if not host:
            continue
        job_id = str(uuid.uuid4())[:8].upper()
        job = {
            "job_id": job_id,
            "cve_id": cve_id,
            "severity": cve["severity"],
            "score": cve["score"],
            "bsrs": aff["bsrs"],
            "priority": aff["priority"],
            "host_id": aff["host_id"],
            "host_name": host["name"],
            "host_ip": host["host"],
            "host_os": host["os"],
            "status": "queued",
            "auto": False,
            "source": "MANUAL",
            "created_at": now_iso(),
            "updated_at": now_iso(),
            "log": [f"[{now_hm()}] Manual job"],
        }
        with lock:
            job_store[job_id] = job
        threading.Thread(target=_dispatch_to_agent, args=(job_id, cve, host), daemon=True).start()
        job_ids.append(job_id)
    return jsonify({"ok": True, "job_ids": job_ids})

@app.post("/api/agent/callback")
def api_callback():
    body = request.get_json(force=True) or {}
    job_id = body.get("job_id", "").upper()
    result = body.get("result", "unknown")
    log = body.get("log", [])
    logging.info(f"Callback: job {job_id} -> {result}")
    with lock:
        job = job_store.get(job_id)
        if job:
            job["status"] = "patched" if result == "success" else "failed"
            job["updated_at"] = now_iso()
            job["log"].extend(log)
            cid = job["cve_id"]
            if cid in cve_store:
                all_jobs = [j for j in job_store.values() if j["cve_id"] == cid]
                if all(j["status"] in ("patched", "failed") for j in all_jobs):
                    if all(j["status"] == "patched" for j in all_jobs):
                        cve_store[cid]["status"] = "patched"
                        cve_store[cid]["patched_at"] = now_iso()
                        add_test_log("success", f"CVE {cid} fully patched")
                    else:
                        cve_store[cid]["status"] = "failed"
    return jsonify({"ok": True})

@app.post("/api/test/inject")
def test_inject():
    body = request.get_json(force=True) or {}
    cve_id = body.get("cve_id", "").strip().upper()
    force = body.get("force", False)
    if not cve_id or not cve_id.startswith("CVE-"):
        return jsonify({"ok": False, "error": "cve_id requis"}), 400
    with lock:
        existing = cve_store.get(cve_id)
    if existing and not force:
        return jsonify({"ok": True, "already_known": True, "cve": existing})
    cve = fetch_single_cve(cve_id)
    if not cve:
        return jsonify({"ok": False, "error": f"{cve_id} not found"}), 404
    result = run_full_pipeline(cve, source_label="TEST-INJECT")
    return jsonify({"ok": True, "cve_id": cve_id, "result": result})

@app.get("/api/test/log")
def get_test_log():
    with lock:
        return jsonify({"ok": True, "log": test_log[-100:]})

@app.post("/api/sync/nvd/today")
def sync_nvd_today():
    imported = sync_nvd_cves()
    return jsonify({"ok": True, "imported": imported, "date": datetime.now(timezone.utc).date().isoformat()})

@app.get("/api/cti/kpis")
def cti_kpis():
    with lock:
        cves = list(cve_store.values())
    total = len(cves)
    mttd_sum, mttd_count = 0, 0
    for c in cves:
        detected = to_aware(c.get("detected_at"))
        published = to_aware(c.get("published"))
        if detected and published:
            delta = (detected - published).total_seconds() / 3600
            if 0 <= delta < 87600:
                mttd_sum += delta
                mttd_count += 1
    mttd = round(mttd_sum / mttd_count, 1) if mttd_count else 0
    mttr_sum, mttr_count = 0, 0
    for c in cves:
        patched = to_aware(c.get("patched_at"))
        detected = to_aware(c.get("detected_at"))
        if patched and detected:
            delta = (patched - detected).total_seconds() / 3600
            if 0 <= delta < 87600:
                mttr_sum += delta
                mttr_count += 1
    mttr = round(mttr_sum / mttr_count, 1) if mttr_count else 0
    kev_total = sum(1 for c in cves if c.get("kev_status"))
    kev_detected = sum(1 for c in cves if c.get("kev_status") and c.get("matched"))
    kev_coverage = round(kev_detected / kev_total * 100, 1) if kev_total else 0
    enriched = sum(1 for c in cves if (c.get("kev_status") is not None) + (c.get("epss_score", 0) > 0) >= 2)
    enrichment_ratio = round(enriched / total * 100, 1) if total else 0
    return jsonify({
        "ok": True,
        "kpis": {
            "mttd_hours": mttd,
            "mttr_hours": mttr,
            "kev_coverage_percent": kev_coverage,
            "enrichment_ratio_percent": enrichment_ratio,
        }
    })

@app.get("/api/compliance")
def compliance():
    return jsonify({
        "ok": True,
        "compliance": {
            "DORA": {"status": "active", "rule": "Operational resilience"},
            "ISO_27001": {"status": "active", "rule": "Vulnerability management"},
            "PCI_DSS": {"status": "active", "rule": "Patch within 30 days"},
        }
    })

@app.get("/api/health")
def api_health():
    with lock:
        stats = {"cves": len(cve_store), "jobs": len(job_store), "hosts": len(HOSTS)}
    return jsonify({"ok": True, "service": "BankShield CTI", "version": "2.1", "stats": stats})

# ─────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("""
╔════════════════════════════════════════════════════════════════╗
║     BankShield CVE Engine — NVD Polling + Toutes les CVE      ║
╠════════════════════════════════════════════════════════════════╣
║  ✅ Polling toutes les {} minutes (dernières 24h)             ║
║  ✅ Stocke TOUTES les CVE avec flag 'matched'                 ║
║  ✅ Exécute pipeline + dispatch uniquement pour les matchées  ║
║  ✅ Dashboard avec filtre "Matchées uniquement"               ║
╚════════════════════════════════════════════════════════════════╝
    """.format(POLL_INTERVAL_MINUTES))
    # Démarrage du polling en arrière-plan
    threading.Thread(target=polling_loop, daemon=True).start()
    # Attendre 5 secondes puis lancer une première synchro du jour
    threading.Thread(target=lambda: time.sleep(5) or sync_nvd_cves(), daemon=True).start()
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
