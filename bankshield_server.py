"""
BankShield CVE Engine — Flask Server COMPLET (SANS SIMULATION)
===============================================================

POST /api/test/inject
  Body: { "cve_id": "CVE-2024-XXXXX" }
  → Interroge la vraie API NVD pour ce CVE précis
  → Compare avec l'inventaire OS (CPE matching)
  → Si match → envoie automatiquement à l'agent PC
  → PAS DE SIMULATION - ÉCHEC RÉEL SI AGENT INJOIGNABLE
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import threading, time, datetime, uuid, requests, os, logging, json

logging.basicConfig(level=logging.INFO, format="%(asctime)s [SERVER] %(message)s")
app = Flask(__name__)
CORS(app)

# ─────────────────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────────────────
NVD_BASE     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CVE_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY  = os.getenv("NVD_API_KEY",  "")
AGENT_URL    = os.getenv("AGENT_URL",    "http://localhost:5001")
SERVER_URL   = os.getenv("SERVER_URL",   "http://10.10.30.10:5000")
POLL_MINUTES = int(os.getenv("POLL_MINUTES", "15"))

# ─────────────────────────────────────────────────────────
#  INVENTAIRE INFRASTRUCTURE BANCAIRE
# ─────────────────────────────────────────────────────────
HOSTS = {
    "srv-web-01": {
        "name": "Serveur Web Principal", "host": "10.10.10.10",
        "os": "Ubuntu 22.04 LTS", "agent": "http://10.10.10.10:5001",
        "cpe": ["apache:http_server","nginx:nginx","openssl:openssl","php:php"],
        "packages": ["apache2","nginx","openssl","php"],
        "tags": ["web","dmz"],
    },
}

# ─────────────────────────────────────────────────────────
#  IN-MEMORY STORE
# ─────────────────────────────────────────────────────────
cve_store  = {}
job_store  = {}
test_log   = []
lock       = threading.Lock()
_last_poll = None

# ─────────────────────────────────────────────────────────
#  UTILS
# ─────────────────────────────────────────────────────────
def now_iso():
    return datetime.datetime.utcnow().isoformat() + "Z"

def now_hm():
    return datetime.datetime.utcnow().strftime("%H:%M:%S")

def add_test_log(level, msg):
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    entry = {"ts": ts, "level": level, "msg": msg}
    with lock:
        test_log.append(entry)
        if len(test_log) > 200:
            test_log.pop(0)
    logging.info(f"[TEST] {msg}")

# ─────────────────────────────────────────────────────────
#  NVD FETCHER — UN SEUL CVE PAR ID
# ─────────────────────────────────────────────────────────
def fetch_single_cve(cve_id: str):
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    params = {"cveId": cve_id}

    add_test_log("info", f"→ Interrogation NVD API: {cve_id}")

    try:
        resp = requests.get(NVD_CVE_BASE, params=params, headers=headers, timeout=15)
        add_test_log("info", f"← NVD réponse HTTP {resp.status_code}")

        if resp.status_code == 404:
            add_test_log("error", f"CVE {cve_id} introuvable")
            return None
        if resp.status_code == 403:
            add_test_log("error", "Accès NVD refusé")
            return None
        if resp.status_code == 429:
            add_test_log("warn", "Rate-limit NVD atteint")
            return None

        resp.raise_for_status()
        data = resp.json()

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            add_test_log("warn", f"Aucune vulnérabilité pour {cve_id}")
            return None

        cve_raw = vulns[0].get("cve", {})
        return _parse_nvd_cve(cve_raw)

    except Exception as e:
        add_test_log("error", f"Erreur NVD: {e}")
        return None

def _parse_nvd_cve(cve_raw: dict) -> dict:
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
            score = cd.get("baseScore", 0.0)
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

    return {
        "id": cve_id,
        "description": desc,
        "score": score,
        "severity": sev.upper() if sev else "UNKNOWN",
        "vector": vector,
        "cpes": cpes,
        "cwes": cwes,
        "references": refs,
        "published": cve_raw.get("published", now_iso()),
        "modified": cve_raw.get("lastModified", now_iso()),
        "source": "NVD",
    }

# ─────────────────────────────────────────────────────────
#  NVD BULK FETCHER
# ─────────────────────────────────────────────────────────
def fetch_nvd_bulk(hours_back: int = 24) -> list[dict]:
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    end = datetime.datetime.utcnow()
    start = end - datetime.timedelta(hours=hours_back)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 100,
    }
    try:
        logging.info(f"[NVD] Bulk poll — last {hours_back}h")
        resp = requests.get(NVD_BASE, params=params, headers=headers, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        total = data.get("totalResults", 0)
        logging.info(f"[NVD] {total} CVE retournées")
        return [_parse_nvd_cve(v.get("cve", {})) for v in data.get("vulnerabilities", []) if v.get("cve")]
    except Exception as e:
        logging.error(f"[NVD] Bulk fetch error: {e}")
        return []

# ─────────────────────────────────────────────────────────
#  CPE MATCHER
# ─────────────────────────────────────────────────────────
def match_hosts(cve: dict) -> list[str]:
    cve_cpes = cve.get("cpes", [])
    cve_desc = cve.get("description", "").lower()
    affected = []

    for host_id, host in HOSTS.items():
        matched = False

        for host_cpe in host.get("cpe", []):
            parts = host_cpe.split(":")
            vendor = parts[0] if len(parts) > 0 else ""
            product = parts[1] if len(parts) > 1 else ""
            for nvd_cpe in cve_cpes:
                if vendor in nvd_cpe and (not product or product in nvd_cpe):
                    matched = True
                    break
            if matched:
                break

        if not matched:
            keywords = []
            for cpe in host.get("cpe", []):
                keywords += cpe.replace("_", " ").replace(":", " ").split()
            for pkg in host.get("packages", []):
                keywords.append(pkg.lower())
            for kw in set(keywords):
                if len(kw) > 3 and kw in cve_desc:
                    matched = True
                    break

        if matched:
            affected.append(host_id)

    return affected

# ─────────────────────────────────────────────────────────
#  PIPELINE COMPLET
# ─────────────────────────────────────────────────────────
def run_full_pipeline(cve: dict, source_label: str = "INJECT") -> dict:
    cve_id = cve["id"]
    affected_hosts = match_hosts(cve)

    cve["affected_hosts"] = affected_hosts
    cve["status"] = "new"
    cve["detected_at"] = now_iso()
    cve["inject_source"] = source_label

    with lock:
        cve_store[cve_id] = cve

    add_test_log("info", f"CVE {cve_id} [{cve['severity']}] score={cve['score']}")

    dispatched_jobs = []

    if affected_hosts:
        add_test_log("warn", f"⚠ {len(affected_hosts)} host(s) affecté(s): {affected_hosts}")

        if cve["severity"] in ("CRITICAL", "HIGH"):
            add_test_log("info", f"→ Dispatch automatique vers les agents")
            for host_id in affected_hosts:
                host = HOSTS.get(host_id)
                if not host:
                    continue
                job_id = str(uuid.uuid4())[:8].upper()
                job = {
                    "job_id": job_id,
                    "cve_id": cve_id,
                    "severity": cve["severity"],
                    "score": cve["score"],
                    "host_id": host_id,
                    "host_name": host["name"],
                    "host_ip": host["host"],
                    "host_os": host["os"],
                    "status": "queued",
                    "auto": True,
                    "source": source_label,
                    "created_at": now_iso(),
                    "updated_at": now_iso(),
                    "log": [f"[{now_hm()}] Job créé — source: {source_label}"],
                }
                with lock:
                    job_store[job_id] = job
                    cve_store[cve_id]["status"] = "analyzing"

                add_test_log("info", f"→ Job {job_id} créé → {host['name']}")
                threading.Thread(
                    target=_dispatch_to_agent,
                    args=(job_id, cve, host),
                    daemon=True
                ).start()
                dispatched_jobs.append(job_id)
        else:
            add_test_log("info", f"Sévérité {cve['severity']} — dispatch manuel requis")
    else:
        add_test_log("info", "Aucun host affecté")

    return {
        "cve_id": cve_id,
        "severity": cve["severity"],
        "score": cve["score"],
        "affected_hosts": affected_hosts,
        "jobs_created": dispatched_jobs,
        "auto_dispatched": len(dispatched_jobs) > 0,
        "description": cve["description"][:200] + "..." if len(cve.get("description", "")) > 200 else cve.get("description", ""),
    }

# ─────────────────────────────────────────────────────────
#  DISPATCH VERS AGENT - SANS SIMULATION
# ─────────────────────────────────────────────────────────
def _dispatch_to_agent(job_id: str, cve: dict, host: dict):
    """Dispatch vers un agent RÉEL - JAMAIS de simulation"""
    payload = {
        "job_id": job_id,
        "cve_id": cve["id"],
        "severity": cve["severity"],
        "score": cve["score"],
        "vector": cve.get("vector", ""),
        "description": cve.get("description", ""),
        "host_os": host["os"],
        "host_id": host.get("host", ""),
        "packages": host.get("packages", []),
        "cpe": host.get("cpe", []),
        "callback_url": f"{SERVER_URL}/api/agent/callback",
        "secret": "bankshield-2024",
    }
    agent_url = host.get("agent", AGENT_URL)

    with lock:
        if job_id in job_store:
            job_store[job_id]["status"] = "dispatched"
            job_store[job_id]["log"].append(f"[{now_hm()}] 📤 Envoi à {agent_url}")

    try:
        resp = requests.post(f"{agent_url}/execute", json=payload, timeout=8)

        if resp.status_code == 200:
            add_test_log("success", f"✓ Job {job_id} accepté par agent")
            with lock:
                if job_id in job_store:
                    job_store[job_id]["status"] = "running"
                    job_store[job_id]["log"].append(f"[{now_hm()}] ✅ Agent a accepté")
        else:
            error_msg = f"❌ Agent HTTP {resp.status_code}"
            with lock:
                if job_id in job_store:
                    job_store[job_id]["status"] = "failed"
                    job_store[job_id]["log"].append(f"[{now_hm()}] {error_msg}")
            add_test_log("error", error_msg)

    except requests.exceptions.ConnectionError:
        # ⚠️ PAS DE SIMULATION - ÉCHEC RÉEL
        error_msg = f"❌ Agent {agent_url} INJOIGNABLE - L'agent doit tourner sur {host['host']}"
        with lock:
            if job_id in job_store:
                job_store[job_id]["status"] = "failed"
                job_store[job_id]["log"].append(f"[{now_hm()}] {error_msg}")
                job_store[job_id]["log"].append(f"[{now_hm()}] 💡 SSH {host['host']} puis: python3 agent.py")
        add_test_log("error", error_msg)

    except requests.exceptions.Timeout:
        error_msg = f"⏱️ Timeout agent {agent_url}"
        with lock:
            if job_id in job_store:
                job_store[job_id]["status"] = "failed"
                job_store[job_id]["log"].append(f"[{now_hm()}] {error_msg}")
        add_test_log("error", error_msg)

    except Exception as e:
        error_msg = f"💥 Erreur: {str(e)}"
        with lock:
            if job_id in job_store:
                job_store[job_id]["status"] = "failed"
                job_store[job_id]["log"].append(f"[{now_hm()}] {error_msg}")
        add_test_log("error", error_msg)


# ⚠️ NOTE: La fonction _simulate_fix a été SUPPRIMÉE - plus jamais de simulation !

# ─────────────────────────────────────────────────────────
#  BACKGROUND POLLING
# ─────────────────────────────────────────────────────────
def _poll_and_process(hours_back: int = 24):
    global _last_poll
    _last_poll = now_iso()
    fresh = fetch_nvd_bulk(hours_back)
    new_c = 0
    for cve in fresh:
        cid = cve["id"]
        with lock:
            known = cid in cve_store
        if not known:
            run_full_pipeline(cve, source_label="NVD-POLL")
            new_c += 1
    logging.info(f"[POLL] {new_c} nouveaux CVE")

def polling_loop():
    _poll_and_process(hours_back=24)
    while True:
        time.sleep(POLL_MINUTES * 60)
        _poll_and_process(hours_back=POLL_MINUTES // 60 + 1)

threading.Thread(target=polling_loop, daemon=True).start()

# ─────────────────────────────────────────────────────────
#  API ROUTES
# ─────────────────────────────────────────────────────────

@app.post("/api/test/inject")
def test_inject():
    body = request.get_json(force=True) or {}
    cve_id = body.get("cve_id", "").strip().upper()
    force = body.get("force", False)
    do_fix = body.get("auto_fix", True)

    if not cve_id:
        return jsonify({"ok": False, "error": "cve_id requis"}), 400

    if not cve_id.startswith("CVE-"):
        return jsonify({"ok": False, "error": "Format invalide"}), 400

    add_test_log("info", f"═══ INJECTION TEST: {cve_id} ═══")
    steps = {}

    with lock:
        existing = cve_store.get(cve_id)

    if existing and not force:
        return jsonify({
            "ok": True,
            "already_known": True,
            "message": f"{cve_id} déjà présent. force=true pour réinjecter.",
            "cve": existing,
        })

    add_test_log("info", "ÉTAPE 1/3 — NVD API...")
    cve = fetch_single_cve(cve_id)

    if cve is None:
        steps["1_nvd_fetch"] = {"ok": False, "error": "CVE introuvable"}
        return jsonify({"ok": False, "error": f"Impossible de récupérer {cve_id}", "steps": steps}), 404

    steps["1_nvd_fetch"] = {
        "ok": True,
        "severity": cve["severity"],
        "score": cve["score"],
        "cpes": len(cve.get("cpes", [])),
    }
    add_test_log("success", f"✓ NVD → {cve_id} [{cve['severity']}]")

    add_test_log("info", "ÉTAPE 2/3 — CPE Matching...")
    affected = match_hosts(cve)
    steps["2_cpe_match"] = {
        "ok": True,
        "total_hosts": len(HOSTS),
        "matched_hosts": affected,
        "match_count": len(affected),
    }
    if affected:
        add_test_log("warn", f"⚠ Match sur {len(affected)} host(s)")
    else:
        add_test_log("info", "Aucun host affecté")

    add_test_log("info", "ÉTAPE 3/3 — Pipeline...")

    if not do_fix:
        cve["affected_hosts"] = affected
        cve["status"] = "new"
        cve["detected_at"] = now_iso()
        cve["inject_source"] = "TEST-NO-FIX"
        with lock:
            cve_store[cve_id] = cve
        steps["3_auto_patch"] = {"ok": True, "skipped": True}
        add_test_log("info", "Injection sans patch")
    else:
        result = run_full_pipeline(cve, source_label="TEST-INJECT")
        steps["3_auto_patch"] = {
            "ok": True,
            "auto_dispatched": result["auto_dispatched"],
            "jobs": result["jobs_created"],
            "job_count": len(result["jobs_created"]),
        }

    with lock:
        final_cve = cve_store.get(cve_id, cve)

    add_test_log("success", f"✓ Pipeline terminé")

    return jsonify({
        "ok": True,
        "cve_id": cve_id,
        "steps": steps,
        "cve": final_cve,
        "summary": {
            "severity": cve["severity"],
            "score": cve["score"],
            "hosts_hit": len(affected),
            "jobs_created": len(steps.get("3_auto_patch", {}).get("jobs", [])),
        },
    })


@app.get("/api/test/log")
def get_test_log():
    with lock:
        entries = list(test_log)
    return jsonify({"ok": True, "count": len(entries), "log": entries[-100:]})


@app.post("/api/test/reset")
def test_reset():
    confirm = (request.get_json(force=True) or {}).get("confirm", False)
    if not confirm:
        return jsonify({"ok": False, "error": "confirm=true requis"}), 400
    with lock:
        cve_store.clear()
        job_store.clear()
        test_log.clear()
    return jsonify({"ok": True, "message": "Store vidé"})


@app.get("/api/test/hosts")
def get_hosts_inventory():
    return jsonify({"ok": True, "count": len(HOSTS), "hosts": HOSTS})


@app.post("/api/test/inject/batch")
def test_inject_batch():
    body = request.get_json(force=True) or {}
    cve_ids = body.get("cve_ids", [])
    do_fix = body.get("auto_fix", True)

    if not cve_ids or not isinstance(cve_ids, list):
        return jsonify({"ok": False, "error": "cve_ids requis"}), 400
    if len(cve_ids) > 10:
        return jsonify({"ok": False, "error": "Maximum 10 CVE"}), 400

    results = {}
    errors = {}

    def _process(cid):
        cid = cid.strip().upper()
        try:
            cve = fetch_single_cve(cid)
            if cve is None:
                errors[cid] = "Introuvable"
                return
            r = run_full_pipeline(cve, source_label="TEST-BATCH")
            results[cid] = {
                "severity": r["severity"],
                "score": r["score"],
                "hosts": r["affected_hosts"],
                "jobs": r["jobs_created"],
            }
        except Exception as e:
            errors[cid] = str(e)

    threads = [threading.Thread(target=_process, args=(cid,), daemon=True) for cid in cve_ids]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)
        time.sleep(0.7 if NVD_API_KEY else 7)

    return jsonify({
        "ok": True,
        "total": len(cve_ids),
        "success": len(results),
        "errors": len(errors),
        "results": results,
        "failed": errors,
    })


@app.get("/api/warn")
def api_warn():
    sev_f = request.args.get("severity", "").upper()
    status_f = request.args.get("status", "")
    with lock:
        items = list(cve_store.values())
    if sev_f:
        items = [c for c in items if c.get("severity") == sev_f]
    if status_f:
        items = [c for c in items if c.get("status") == status_f]
    items.sort(key=lambda c: c.get("score", 0), reverse=True)
    summary = {
        "total": len(items),
        "critical": sum(1 for c in items if c.get("severity") == "CRITICAL"),
        "high": sum(1 for c in items if c.get("severity") == "HIGH"),
        "medium": sum(1 for c in items if c.get("severity") == "MEDIUM"),
        "affected": sum(1 for c in items if c.get("affected_hosts")),
        "patched": sum(1 for c in items if c.get("status") == "patched"),
        "last_poll": _last_poll,
    }
    return jsonify({"ok": True, "summary": summary, "cves": items})


@app.post("/api/auto_fix")
def api_auto_fix():
    body = request.get_json(force=True) or {}
    cve_id = body.get("cve_id", "").strip()
    if not cve_id:
        return jsonify({"ok": False, "error": "cve_id requis"}), 400
    with lock:
        cve = cve_store.get(cve_id)
    if not cve:
        return jsonify({"ok": False, "error": f"{cve_id} non trouvé"}), 404
    if cve.get("status") == "patched":
        return jsonify({"ok": True, "message": "Déjà patché"})

    job_ids = []
    for host_id in cve.get("affected_hosts", []):
        host = HOSTS.get(host_id)
        if not host:
            continue
        job_id = str(uuid.uuid4())[:8].upper()
        job = {
            "job_id": job_id,
            "cve_id": cve_id,
            "severity": cve["severity"],
            "score": cve["score"],
            "host_id": host_id,
            "host_name": host["name"],
            "host_ip": host["host"],
            "host_os": host["os"],
            "status": "queued",
            "auto": False,
            "source": "MANUAL",
            "created_at": now_iso(),
            "updated_at": now_iso(),
            "log": [f"[{now_hm()}] Job créé manuellement"],
        }
        with lock:
            job_store[job_id] = job
            cve_store[cve_id]["status"] = "analyzing"
        threading.Thread(target=_dispatch_to_agent, args=(job_id, cve, host), daemon=True).start()
        job_ids.append(job_id)
    return jsonify({"ok": True, "job_ids": job_ids, "hosts": len(job_ids)})


@app.post("/api/agent/callback")
def api_callback():
    body = request.get_json(force=True) or {}
    job_id = body.get("job_id", "").upper()
    result = body.get("result", "unknown")
    log = body.get("log", [])

    with lock:
        job = job_store.get(job_id)
        if job:
            if result == "success":
                job["status"] = "patched"
                add_test_log("success", f"✅ Job {job_id} RÉELLEMENT corrigé")
            else:
                job["status"] = "failed"
                add_test_log("error", f"❌ Job {job_id} échec réel")

            job["updated_at"] = now_iso()
            job["log"].extend(log)

            cid = job["cve_id"]
            if cid in cve_store:
                all_jobs = [j for j in job_store.values() if j["cve_id"] == cid]
                all_completed = all(j["status"] in ("patched", "failed") for j in all_jobs)

                if all_completed:
                    all_success = all(j["status"] == "patched" for j in all_jobs)
                    if all_success:
                        cve_store[cid]["status"] = "patched"
                        cve_store[cid]["patched_at"] = now_iso()
                        add_test_log("success", f"🎯 CVE {cid} entièrement corrigé")
                    else:
                        cve_store[cid]["status"] = "failed"
                        add_test_log("error", f"⚠️ CVE {cid} échec - correction manuelle requise")

    return jsonify({"ok": True})


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
        status = "ok"
        if any(c for c in cves if hid in c.get("affected_hosts", []) and c.get("status") != "patched" and c["severity"] == "CRITICAL"):
            status = "critical"
        elif active:
            status = "warning"
        result[hid] = {**h, "status": status, "active_cves": active, "cve_count": len(active)}
    return jsonify({"ok": True, "hosts": result})


@app.post("/api/poll")
def api_poll():
    hours = int((request.get_json(force=True, silent=True) or {}).get("hours", 24))
    threading.Thread(target=_poll_and_process, args=(hours,), daemon=True).start()
    return jsonify({"ok": True, "message": f"Poll lancé"})


@app.get("/api/debug/agent-status")
def debug_agent_status():
    """Vérifie quels agents sont réellement joignables"""
    results = {}
    for host_id, host in HOSTS.items():
        agent_url = host.get("agent", AGENT_URL)
        try:
            resp = requests.get(f"{agent_url}/health", timeout=3)
            if resp.status_code == 200:
                results[host_id] = {
                    "status": "✅ ONLINE",
                    "url": agent_url,
                    "name": host["name"],
                    "response": resp.json()
                }
            else:
                results[host_id] = {
                    "status": "❌ ERROR",
                    "url": agent_url,
                    "name": host["name"],
                    "error": f"HTTP {resp.status_code}"
                }
        except Exception as e:
            results[host_id] = {
                "status": "❌ OFFLINE",
                "url": agent_url,
                "name": host["name"],
                "error": str(e)[:100]
            }

    online = sum(1 for r in results.values() if "✅" in r["status"])
    return jsonify({
        "total": len(HOSTS),
        "online": online,
        "offline": len(HOSTS) - online,
        "agents": results
    })


@app.get("/api/health")
def api_health():
    with lock:
        total = len(cve_store)
        jobs = len(job_store)
    return jsonify({
        "ok": True,
        "service": "BankShield CVE Engine",
        "cves": total,
        "jobs": jobs,
        "last_poll": _last_poll,
        "nvd_key": bool(NVD_API_KEY),
        "poll_interval_min": POLL_MINUTES,
    })


if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════╗
║     BankShield CVE Engine — Flask Server            ║
╠══════════════════════════════════════════════════════╣
║  ✅ SANS SIMULATION                                 ║
║  ✅ Agent injoignable → ÉCHEC RÉEL                  ║
║  ✅ Debug: /api/debug/agent-status                  ║
╠══════════════════════════════════════════════════════╣
║  POST /api/test/inject                              ║
║  Body: { "cve_id": "CVE-2024-XXXXX" }              ║
╚══════════════════════════════════════════════════════╝
""")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
