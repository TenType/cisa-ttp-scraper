import json
import re
from datetime import date, datetime
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from mitreattack.stix20 import MitreAttackData
from rich.console import Console
from stix2 import MemoryStore

BASE = "https://www.cisa.gov"
INDEX = "https://www.cisa.gov/news-events/cybersecurity-advisories?f[0]=advisory_type%3A94"
MITRE_ENTERPRISE_ATTACK = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
MITRE_MOBILE_ATTACK = "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json"
MITRE_ICS_ATTACK = "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json"

console = Console()
print = console.print


def fetch(url: str, timeout: int = 30) -> str:
    resp = requests.get(url, timeout=timeout)
    resp.raise_for_status()
    return resp.text


def parse_advisory_page(html: str) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    title = "(no title)"
    h1 = soup.find("h1")
    if h1 and h1.get_text(strip=True):
        title = h1.get_text(strip=True)

    date_text = "(no date)"
    time_tag = soup.find("time")
    if time_tag and time_tag.get_text(strip=True):
        date_text = time_tag.get_text(strip=True)

    return {"title": title, "date": date_text}


def parse_date(date_text: str | None) -> date | None:
    if not date_text:
        return None
    # capture formats like 'OCT 09, 2025', 'Oct 9, 2025', 'February 01, 2024'
    m = re.search(r"([A-Za-z]{3,9}\s+\d{1,2},\s+\d{4})", date_text)
    if not m:
        return None
    s = m.group(1)
    for fmt in ("%b %d, %Y", "%B %d, %Y"):
        try:
            return datetime.strptime(s, fmt).date()
        except ValueError:
            continue
    return None


def contains_ttps(text: str) -> bool:
    return bool(re.search(r"\b(T\d{4}(?:\.\d{1,3})?)\b", text))


def extract_advisory_fields(html: str, mitre_attack_data: MitreAttackData) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    
    def get_matching_keywords(soup: BeautifulSoup, keywords: list[str]) -> str:
        for hdr in soup.find_all(re.compile(r"^h[1-6]$")):
            txt = hdr.get_text(strip=True).lower()
            if any(k in txt for k in keywords):
                parts: list[str] = []
                hdr_level = int(hdr.name[1])

                # Walk document-order from the header forward. For each element we check
                # whether that element or any of its ancestor tags is a header. If we
                # encounter any header (other than the originating header) whose level
                # is <= hdr_level, we stop collecting. Lower-level headers (level >
                # hdr_level) are included when encountered.
                for elem in hdr.next_elements:
                    # Only consider Tag elements
                    name = getattr(elem, "name", None)
                    if not name:
                        continue

                    # If this element is a header itself, or has a header ancestor, find it
                    header_anc = None
                    if re.match(r"^h[1-6]$", name, flags=re.I):
                        header_anc = elem
                    else:
                        header_anc = elem.find_parent(re.compile(r"^h[1-6]$"))

                    # If we found a header ancestor that's not the original header,
                    # decide whether to stop or include the header text.
                    if header_anc and header_anc is not hdr:
                        anc_level = int(getattr(header_anc, "name")[1])
                        if anc_level <= hdr_level:
                            # Reached same-or-higher-level header anywhere in subtree -> stop
                            break
                        # Lower-level header: include its text when we encounter the header tag
                        if elem is header_anc:
                            t = header_anc.get_text(separator=" ", strip=True)
                            if t:
                                parts.append(t)
                        # continue scanning after handling header tag
                        continue

                    # Collect paragraph-like content (p, ul, ol, div)
                    if name in ("p", "ul", "ol", "div"):
                        # If this element contains a header descendant, handle specially:
                        # - if it contains a same-or-higher-level header, stop (we've reached
                        #   the next section)
                        # - if it contains only lower-level headers, skip appending the
                        #   container's aggregated text (the lower-level headers will be
                        #   handled when encountered as elements)
                        hdr_desc = None
                        if hasattr(elem, "find"):
                            hdr_desc = getattr(elem, "find")(re.compile(r"^h[1-6]$"))
                        if hdr_desc:
                            desc_level = int(getattr(hdr_desc, "name")[1])
                            if desc_level <= hdr_level:
                                break
                            # lower-level header descendant: don't append container text
                            # (we'll handle the header element itself when we reach it)
                            continue

                        t = elem.get_text(separator=" ", strip=True)
                        if t:
                            parts.append(t)
                            
                if len(parts) == 0:
                    print(f"    :warning: Unable to capture content in section matching {keywords}", style="yellow")
                return "\n\n".join(parts).strip()
            
        print(f"    :warning: Cannot find header matching {keywords}", style="yellow")
        return ""

    def get_summary(soup: BeautifulSoup) -> str:
        return get_matching_keywords(soup, ["executive summary", "introduction", "summary", "overview"])

    def get_mitre_info(mitre_attack_data: MitreAttackData, tid: str) -> tuple[str, list[str]]:
        technique = mitre_attack_data.get_object_by_attack_id(tid, "attack-pattern")
        if technique:
            tactics = [t.phase_name for t in technique.kill_chain_phases] # type: ignore
            return technique.name, tactics # type: ignore

        name = scrape_mitre_name(tid)
        if name:
            print(f"    :warning: Deprecated TTP, no tactics found: {tid}", style="yellow")
            return name, []
        
        print(f"    :warning: No info found for TTP: {tid}", style="yellow")
        return "", []
    
    def scrape_mitre_name(tid: str) -> str | None:
        # Try a few MITRE ATT&CK technique URL patterns to find a canonical name.
        # Some MITRE technique pages redirect using a client-side meta-refresh; follow those.
        MITRE_BASE = "https://attack.mitre.org"
        candidates = []
        if "." in tid:
            base, sub = tid.split(".", 1)
            sub = sub.zfill(3)
            candidates.append(f"{MITRE_BASE}/techniques/{base}/{sub}/")
            candidates.append(f"{MITRE_BASE}/techniques/{base}/")
        else:
            candidates.append(f"{MITRE_BASE}/techniques/{tid}/")

        max_follow = 5
        for start_url in candidates:
            current_url = start_url
            for _ in range(max_follow):
                try:
                    resp_text = fetch(current_url)
                except requests.HTTPError:
                    break

                s = BeautifulSoup(resp_text, "html.parser")
                # If we have an <h1>, prefer that as the canonical title
                h1 = s.find("h1")
                if h1 and h1.get_text(strip=True):
                    text = h1.get_text(strip=True)
                    return re.sub(r":(?!:)", ": ", text)

                # Look for meta refresh redirects and follow them if present
                meta = s.find("meta")
                if meta and meta.get("content"):
                    content = str(meta.get("content"))
                    murl = re.search(r"url=(.+)$", content, flags=re.I)
                    if murl:
                        target = murl.group(1).strip().strip('"').strip("'")
                        # build absolute URL for relative redirects
                        current_url = urljoin(MITRE_BASE, target)
                        # follow the redirect (loop)
                        continue
                break
        return None

    def get_ttps(soup: BeautifulSoup, mitre_attack_data: MitreAttackData) -> list[dict]:
        ttps: list[dict] = []
        text_blob = soup.get_text(separator=" ", strip=True)
        for m in re.finditer(r"\b(T\d{4}(?:\.\d{1,3})?)\b", text_blob):
            tid = m.group(1)
            if not any(t.get("id") == tid for t in ttps):
                name, tactics = get_mitre_info(mitre_attack_data, tid)
                ttps.append({"name": name, "id": tid, "tactics": tactics})
        return ttps

    def get_mitigations(soup: BeautifulSoup) -> str:
        return get_matching_keywords(soup, ["mitigation"])


    summary = get_summary(soup)
    mitigations = get_mitigations(soup)
    ttps = get_ttps(soup, mitre_attack_data)

    return {"title": "(no title)", "source": "cisa", "url": "(no url)", "date": "(no date)", "summary": summary, "mitigations": mitigations, "ttps": ttps}


def get_index_items(url: str):
    html = fetch(url)
    soup = BeautifulSoup(html, "html.parser")
    # common listing anchors live under h3 or h2 tags on this page
    for a in soup.select("h3 a, h2 a, .views-row a, article a"):
        href = a.get("href")
        title = a.get_text(strip=True)
        if not href or not title:
            continue
        yield urljoin(BASE, str(href))

def prepare_mitre_attack_data() -> MitreAttackData:
    mem_store = MemoryStore()

    print("  :inbox_tray: Loading Enterprise", style="bright_black")
    enterprise_json = json.loads(fetch(MITRE_ENTERPRISE_ATTACK))
    mem_store.add(enterprise_json)

    print("  :inbox_tray: Loading Mobile", style="bright_black")
    mobile_json = json.loads(fetch(MITRE_MOBILE_ATTACK))
    mem_store.add(mobile_json)

    print("  :inbox_tray: Loading ICS", style="bright_black")
    ics_json = json.loads(fetch(MITRE_ICS_ATTACK))
    mem_store.add(ics_json)

    return MitreAttackData(src=mem_store)


def scrape(max_pages = 17, cutoff = date(2017, 1, 1)) -> tuple[list[dict], int]:
    print(":books: Preparing MITRE ATT&CK data files", style="bright_black")
    mitre_attack_data = prepare_mitre_attack_data()

    matches: list[dict] = []
    total_ttps = 0
    # maintain a set of normalized title+date keys for deduplication
    seen_keys: set = set()
    
    for p in range(0, max_pages):
        page_url = f"{INDEX}&page={p}"
        print(f":file_folder: Scanning index page {p}/{max_pages-1} -> {page_url}", style="bright_black")
        for item_url in get_index_items(page_url):
            try:
                html = fetch(item_url)
            except Exception as e:
                print(f":x: Failed to fetch {item_url}: {e}", style="bright_black")
                continue

            parsed = parse_advisory_page(html)
            d = parse_date(parsed["date"])
            if d is None:
                print(f":warning: No date found: {item_url}", style="yellow")
                continue
            if d < cutoff:
                print(f":date: Reached date cutoff of {cutoff.isoformat()}, quitting", style="bright_black")
                return matches, total_ttps

            if contains_ttps(html):
                print(f"  :mag: Found page with TTPs -> {item_url}", style="bright_black")
                key = f"{parsed["title"]}||{d.isoformat()}"
                if key in seen_keys:
                    print(f"    :warning: Skipping duplicate advisory {parsed["title"]} ({d.isoformat()})", style="yellow")
                else:
                    fields = extract_advisory_fields(html, mitre_attack_data)
                    fields["title"] = parsed["title"]
                    fields["date"] = d.isoformat()
                    fields["url"] = item_url
                    seen_keys.add(key)
                    matches.append(fields)

                    num_ttps = len(fields["ttps"])
                    print(f"    :pick: Extracted {num_ttps} TTPs", style="bright_black")
                    total_ttps += num_ttps
            else:
                print(f"  :heavy_minus_sign: No TTPs found        -> {item_url}", style="bright_black")

    return matches, total_ttps

def main() -> None:
    matches, total_ttps = scrape()
    output_file = "out.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(matches, f, indent=2)
    print(f"Wrote {len(matches)} matching advisories to {output_file} with {total_ttps} total TTPs")


if __name__ == "__main__":
    main()
