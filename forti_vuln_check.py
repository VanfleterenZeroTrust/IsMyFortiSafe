#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fortinet Vulnerability Checker — CSV + Colored Dashboard
Inline Detail + Per-Asset Header Refresh + Cute Loading Bar (>1s)

- CSV headers: name,product,version
- Severity filters (mutually exclusive): --critical | --high | --medium | --low
  * With --detail: table header shown once at top, then again after each asset block
  * Column shows ONLY the chosen severity (+ centered Status)
- No filter: shows all 4 severity columns; --dashboard prints totals
- Loading bar: shown during CVE fetch if total runtime exceeds 1s
"""
import argparse, csv, json, os, sys, time, re
from typing import Dict, List

try:
    import requests
except ImportError:
    print("Missing dependency: requests. Install with: sudo apt-get install -y python3-requests", file=sys.stderr)
    sys.exit(2)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

INFER_PART = {
    "fortios":"o","fortiproxy":"o","fortianalyzer":"o","fortimanager":"o","fortiweb":"o","fortimail":"o","fortiauthenticator":"o",
    "fortiswitch":"o","fortiap":"o","fortiadc":"o","fortivoice":"o",
    "forticlient":"a","fortiedr":"a","fortisiem":"a","fortitoken":"a"
}

# ---------- Color helpers ----------
class Colors:
    def __init__(self, enabled: bool):
        if not enabled:
            self.reset = self.bold = ""
            self.red = self.yellow = self.cyan = self.green = self.gray = self.orange = self.red_orange = ""
            self.blue = ""
        else:
            self.reset = "\033[0m"; self.bold = "\033[1m"
            self.red = "\033[31m"; self.yellow = "\033[33m"; self.cyan = "\033[36m"
            self.green = "\033[32m"; self.gray = "\033[90m"; self.blue = "\033[34m"
            self.orange = "\033[38;5;208m"; self.red_orange = "\033[38;5;203m"

def make_colors(no_color: bool) -> Colors:
    return Colors(sys.stdout.isatty() and not no_color)

# ---------- Helpers ----------
def nvd_headers() -> Dict[str,str]:
    h = {"User-Agent":"Kali-FortiVulnCheck/3.6 (+local)"}
    if os.getenv("NVD_API_KEY"): h["apiKey"] = os.getenv("NVD_API_KEY")
    return h

def build_cpe(product: str, version: str, vendor: str="fortinet") -> str:
    prod = (product or "").strip().lower()
    part = INFER_PART.get(prod,"o"); v = (version or "").strip()
    vend = (vendor or "fortinet").strip().lower()
    return f"cpe:2.3:{part}:{vend}:{prod}:{v}:*:*:*:*:*:*:*"

def extract_cvss(cve_obj: dict):
    metrics = cve_obj.get("metrics",{})
    def pick(k):
        arr = metrics.get(k) or []
        if arr and isinstance(arr,list):
            d = arr[0].get("cvssData",{})
            sev = (str(d.get("baseSeverity","")).upper() or "UNKNOWN")
            score = d.get("baseScore")
            try: score = float(score) if score is not None else None
            except: score = None
            return sev, score
        return None
    for k in ("cvssMetricV40","cvssMetricV4","cvssMetricV31","cvssMetricV30","cvssMetricV2"):
        r = pick(k)
        if r: return r
    return "UNKNOWN", None

def english_desc(cve: dict) -> str:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value","").strip()
    return ""

def short_risk(text: str) -> str:
    t = text or ""
    t = re.sub(r"\bversions?\s+[\d\w\.\- ,]*(?:through|to)\s+[\d\w\.\- ,]+", "", t, flags=re.IGNORECASE)
    t = re.sub(r"\b\d+(?:\.\d+){1,}\b", "", t)
    t = re.sub(r"\s{2,}", " ", t).strip()
    lower = t.lower()
    rules = [
        (r"remote code execution|rce|execute (arbitrary|unauthorized) code|code execution", "remote code execution"),
        (r"command injection|os command injection", "command injection"),
        (r"sql injection", "SQL injection"),
        (r"authentication bypass|bypass authentication|auth.?bypass", "authentication bypass"),
        (r"privilege escalation|elevation of privilege|gain higher privileges", "privilege escalation"),
        (r"cross[- ]site scripting|xss", "cross-site scripting"),
        (r"path traversal|directory traversal", "path traversal"),
        (r"information disclosure|exposes? information|leak(s)? information|data leak|sensitive information", "information disclosure"),
        (r"denial of service|dos\b|crash(es)?|consume(?:s)? resources", "denial of service"),
        (r"buffer overflow|heap overflow|stack overflow|out[- ]of[- ]bounds|oob", "memory corruption"),
        (r"improper access control|insufficient access control|authorization", "access control weakness"),
        (r"csrf|cross[- ]site request forgery", "CSRF"),
        (r"ssrf|server[- ]side request forgery", "SSRF"),
        (r"xxe|external entity", "XXE"),
    ]
    for pat, label in rules:
        if re.search(pat, lower): return label
    first = t.split(". ")[0].strip(". "); words = first.split()
    return " ".join(words[:8]) if words else "security issue"

def fetch_all_cves_for_cpe(cpe: str, per_page=200, max_pages=50) -> List[dict]:
    start, collected, tries = 0, [], 0
    session = requests.Session()
    while True:
        params = {"cpeName": cpe, "resultsPerPage": per_page, "startIndex": start}
        try:
            r = session.get(NVD_BASE, headers=nvd_headers(), params=params, timeout=30)
        except requests.exceptions.RequestException:
            if tries < 5: time.sleep(2**tries); tries += 1; continue
            raise
        if r.status_code == 200:
            tries = 0; data = r.json()
            vulns = data.get("vulnerabilities",[]); collected.extend(vulns)
            total = data.get("totalResults", len(collected)); start += per_page
            if start >= total or (start // per_page) >= max_pages: break
            time.sleep(0.4)
        elif r.status_code in (429,) or r.status_code >= 500:
            if tries < 6: time.sleep(min(60,2**tries)); tries += 1; continue
            else: print(f"[!] NVD error {r.status_code}, giving up.", file=sys.stderr); break
        else:
            print(f"[!] NVD error {r.status_code}: {r.text[:200]}", file=sys.stderr); break
    return collected

def load_inventory(path: str):
    items = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            name = (row.get("name") or "").strip()
            product = (row.get("product") or "").strip()
            version = (row.get("version") or "").strip()
            if name and product and version:
                items.append({"name": name, "product": product, "version": version})
    if not items: raise ValueError("Inventory empty or headers missing: name,product,version")
    return items

# ---------- Formatting ----------
def center_color_text(text: str, width: int, color: str, reset: str):
    s = str(text); pad = max(0, width - len(s))
    left = pad // 2; right = pad - left
    return " " * left + color + s + reset + " " * right

# ---------- Cute loading bar ----------
def render_progress(i: int, total: int, C: Colors, start_time: float, prefix="Loading CVEs"):
    """
    Show a progress bar if more than 1s elapsed since start_time.
    """
    elapsed = time.time() - start_time
    if elapsed < 1.0:
        return False  # not shown
    bar_w = 34
    ratio = 0 if total == 0 else min(1.0, max(0.0, i / total))
    filled = int(bar_w * ratio)
    spinner = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    spin = spinner[int(time.time() * 10) % len(spinner)]
    bar = "█" * filled + "░" * (bar_w - filled)
    msg = f"\r{C.cyan}{prefix}{C.reset}  {C.blue}[{bar}]{C.reset}  {int(ratio*100):3d}% {C.gray}{spin}{C.reset}"
    sys.stdout.write(msg)
    sys.stdout.flush()
    return True

def clear_progress_line():
    sys.stdout.write("\r" + " " * 80 + "\r")
    sys.stdout.flush()

# ---------- Main ----------
def main():
    ap = argparse.ArgumentParser(description="Check Fortinet inventory for CVEs and show a colored dashboard.")
    ap.add_argument("-i","--inventory",required=True)
    ap.add_argument("--dashboard",action="store_true")
    grp = ap.add_mutually_exclusive_group()
    grp.add_argument("--critical",action="store_true")
    grp.add_argument("--high",action="store_true")
    grp.add_argument("--medium",action="store_true")
    grp.add_argument("--low",action="store_true")
    ap.add_argument("--detail",action="store_true",help="With a severity flag, show inline CVEs and repeat header after each asset block.")
    ap.add_argument("--json")
    ap.add_argument("--no-color",action="store_true")
    args = ap.parse_args()

    C = make_colors(args.no_color)

    try:
        inventory = load_inventory(args.inventory)
    except Exception as e:
        print(f"Error reading inventory: {e}", file=sys.stderr); sys.exit(2)

    # build results (with progress bar)
    results = []
    any_flagged = False
    total_assets = len(inventory)
    start_time = time.time()
    progress_shown = False

    for idx, item in enumerate(inventory, start=1):
        # maybe show/update progress
        shown_now = render_progress(idx-1, total_assets, C, start_time)
        progress_shown = progress_shown or shown_now

        cpe = build_cpe(item["product"], item["version"])
        cves = fetch_all_cves_for_cpe(cpe)

        sev_counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
        details = {"CRITICAL":[], "HIGH":[], "MEDIUM":[], "LOW":[]}

        for entry in cves:
            cve = entry.get("cve",{})
            cve_id = cve.get("id","UNKNOWN")
            sev, _ = extract_cvss(cve)
            if sev in sev_counts:
                sev_counts[sev] += 1
                desc = english_desc(cve)
                details[sev].append({"id": cve_id, "risk": short_risk(desc)})

        crit, high, med, low = sev_counts.values()
        flagged = (crit + high + med) > 0
        any_flagged = any_flagged or flagged
        results.append({
            "name": item["name"], "product": item["product"], "version": item["version"],
            "sev_counts": sev_counts, "flagged": flagged, "details": details
        })

        # update progress after processing this asset
        shown_now = render_progress(idx, total_assets, C, start_time)
        progress_shown = progress_shown or shown_now

    # clear the progress line if we showed it
    if progress_shown:
        clear_progress_line()

    # active filter
    active_filter = None; label = "Severity"
    def color_for(n: int) -> str: return C.green
    if args.critical:
        active_filter, label = "CRITICAL", "Critical"; color_for = lambda n: (C.red if n>0 else C.green)
    elif args.high:
        active_filter, label = "HIGH", "High"; color_for = lambda n: (C.red_orange if n>0 else C.green)
    elif args.medium:
        active_filter, label = "MEDIUM", "Medium"; color_for = lambda n: (C.orange if n>0 else C.green)
    elif args.low:
        active_filter, label = "LOW", "Low"; color_for = lambda n: (C.yellow if n>0 else C.green)

    # widths, header/separator
    W_NAME, W_PROD, W_VER, W_NUM, GAP = 22, 14, 10, 9, 8
    def make_header():
        return f"{C.bold}{'Name':{W_NAME}} {'Product':{W_PROD}} {'Version':{W_VER}} {label:^{W_NUM}}{'':{GAP}}{'Status':^10}{C.reset}"
    def make_header_full():
        return f"{C.bold}{'Name':{W_NAME}} {'Product':{W_PROD}} {'Version':{W_VER}} {'Critical':^{W_NUM}} {'High':^{W_NUM}} {'Medium':^{W_NUM}} {'Low':^{W_NUM}}{'':{GAP}}{'Status':^10}{C.reset}"
    def sep(total_width): return C.gray + ("─" * total_width) + C.reset

    if active_filter:
        total_w = W_NAME + 1 + W_PROD + 1 + W_VER + 1 + W_NUM + GAP + 10
        print(sep(total_w))
        top_header = make_header()
        print(top_header)
        print(sep(total_w))
    else:
        total_w = W_NAME + 1 + W_PROD + 1 + W_VER + 1 + (W_NUM+1)*4 + GAP + 10
        print(sep(total_w))
        print(make_header_full())
        print(sep(total_w))

    # filter list for detail/iter
    def passes(r):
        if active_filter == "CRITICAL": return r["sev_counts"]["CRITICAL"] > 0
        if active_filter == "HIGH":     return r["sev_counts"]["HIGH"] > 0
        if active_filter == "MEDIUM":   return r["sev_counts"]["MEDIUM"] > 0
        if active_filter == "LOW":      return r["sev_counts"]["LOW"] > 0
        return True

    filtered = [r for r in results if passes(r)]

    for idx, r in enumerate(filtered):
        name = f"{r['name'][:W_NAME]:{W_NAME}}"
        prod = f"{r['product'][:W_PROD]:{W_PROD}}"
        ver  = f"{r['version'][:W_VER]:{W_VER}}"
        crit = r["sev_counts"]["CRITICAL"]; high = r["sev_counts"]["HIGH"]
        med  = r["sev_counts"]["MEDIUM"];  low  = r["sev_counts"]["LOW"]

        status_text = "VULNERABLE" if r["flagged"] else "OK"
        status_color = C.red if r["flagged"] else C.green
        status = center_color_text(status_text, 10, status_color, C.reset)

        if active_filter:
            n = {"CRITICAL":crit,"HIGH":high,"MEDIUM":med,"LOW":low}[active_filter]
            cell = center_color_text(n, W_NUM, color_for(n), C.reset)
            print(f"{name} {prod} {ver} {cell}{' ' * GAP}{status}")

            if args.detail and n > 0:
                indent = " " * 2
                for e in r["details"][active_filter]:
                    print(f"{indent}- {C.bold}{e['id']}{C.reset} — {e['risk']}")

            # after finishing this asset’s CVEs, if another asset follows, print separator + header again
            if args.detail and idx < len(filtered) - 1:
                print(sep(total_w))
                print(make_header())
                print(sep(total_w))
        else:
            def col(n, sev):
                colr = {"CRITICAL": (C.red if n>0 else C.green),
                        "HIGH":     (C.red_orange if n>0 else C.green),
                        "MEDIUM":   (C.orange if n>0 else C.green),
                        "LOW":      (C.yellow if n>0 else C.green)}[sev]
                return center_color_text(n, W_NUM, colr, C.reset)
            print(f"{name} {prod} {ver} {col(crit,'CRITICAL')} {col(high,'HIGH')} {col(med,'MEDIUM')} {col(low,'LOW')}{' ' * GAP}{status}")

    print(sep(total_w))

    if args.dashboard and not active_filter:
        totals = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
        for r in results:
            for k in totals: totals[k] += r["sev_counts"][k]
        print(f"{C.bold}Dashboard (all assets){C.reset}")
        print(f"  {C.red}Critical{C.reset}: {totals['CRITICAL']}   "
              f"{C.red_orange}High{C.reset}: {totals['HIGH']}   "
              f"{C.orange}Medium{C.reset}: {totals['MEDIUM']}   "
              f"{C.yellow}Low{C.reset}: {totals['LOW']}")

    if args.json:
        with open(args.json,"w",encoding="utf-8") as f:
            json.dump(results,f,indent=2,ensure_ascii=False)
        print(f"Wrote JSON results to {args.json}")

    sys.exit(1 if any_flagged else 0)

if __name__ == "__main__":
    main()
