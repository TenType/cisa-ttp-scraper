import json
import re
from datetime import date, datetime
from typing import List
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from requests import HTTPError
from rich.console import Console

BASE = "https://www.cisa.gov"
INDEX = "https://www.cisa.gov/news-events/cybersecurity-advisories?f[0]=advisory_type%3A94"

console = Console()
print = console.print


def fetch(url: str, timeout: int = 30) -> str:
    resp = requests.get(url, timeout=timeout)
    resp.raise_for_status()
    return resp.text


def parse_advisory_page(html: str) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    title = None
    h1 = soup.find("h1")
    if h1 and h1.get_text(strip=True):
        title = h1.get_text(strip=True)

    date_text = None
    time_tag = soup.find("time")
    if time_tag and time_tag.get_text(strip=True):
        date_text = time_tag.get_text(strip=True)

    return {"title": title, "date_text": date_text, "body_text": html}


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
    # if re.search(r"\bTTPs?\b", text, flags=re.I):
    #     return True
    # if re.search(r"Tactics,?\s*Techniques,?\s*and\s*Procedures", text, flags=re.I):
    #     return True
    # if re.search(r"MITRE\s*ATT&CK\s*Tactics\s*and\s*Techniques", text, flags=re.I):
    #     return True
    # return False


def extract_advisory_fields(html: str, url: str) -> dict:
    soup = BeautifulSoup(html, "html.parser")

    def get_title(soup: BeautifulSoup) -> str:
        h1 = soup.find("h1")
        if h1 and h1.get_text(strip=True):
            return h1.get_text(strip=True)
        h2 = soup.find("h2")
        return h2.get_text(strip=True) if h2 and h2.get_text(strip=True) else "(no title)"
    
    def get_matching_keywords(soup: BeautifulSoup, keywords: List[str]) -> str:
        for hdr in soup.find_all(re.compile(r"^h[1-6]$")):
            txt = hdr.get_text(strip=True).lower()
            if any(k in txt for k in keywords):
                parts = []
                hdr_level = int(hdr.name[1])
                for sib in hdr.find_next_siblings():
                    # Stop if we reach a header of the same or higher level
                    if re.match(r"h[1-6]", sib.name):
                        sib_level = int(sib.name[1])
                        if sib_level <= hdr_level:
                            break
                        # If lower-level header, include its text
                        t = sib.get_text(separator=" ", strip=True)
                        if t:
                            parts.append(t)
                        continue
                    if sib.name in ("p", "div", "ul", "ol"):
                        t = sib.get_text(separator=" ", strip=True)
                        if t:
                            parts.append(t)
                return "\n\n".join(parts).strip()
        return ""

    def get_summary(soup: BeautifulSoup) -> str:
        return get_matching_keywords(soup, ["executive summary", "introduction", "summary", "overview"])

    def fetch_mitre_title(tid: str) -> str:
        # Try a few MITRE ATT&CK technique URL patterns to find a canonical title.
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
                except HTTPError:
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

        print(f":warning: No title found for TTP: {tid}", style="red")
        return ""

    def get_ttps(soup: BeautifulSoup) -> List[dict]:
        ttps: List[dict] = []
        text_blob = soup.get_text(separator=" ", strip=True)
        for m in re.finditer(r"\b(T\d{4}(?:\.\d{1,3})?)\b", text_blob):
            tid = m.group(1)
            if not any(t.get("id") == tid for t in ttps):
                ttps.append({"name": fetch_mitre_title(tid), "id": tid})
        return ttps

    def get_mitigations(soup: BeautifulSoup) -> str:
        return get_matching_keywords(soup, ["mitigation"])


    title = get_title(soup)
    summary = get_summary(soup)
    mitigations = get_mitigations(soup)
    ttps = get_ttps(soup)
    print(f"    :pick: Extracted {len(ttps)} TTPs", style="bright_black")

    return {"title": title, "url": url, "date": "(no date)", "summary": summary, "mitigations": mitigations, "ttps": ttps}


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


def scrape(max_pages = 17, cutoff = date(2017, 1, 1)) -> List[dict]:
    matches: List[dict] = []
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
            d = parse_date(parsed.get("date_text"))
            if d is None:
                print(f":warning: No date found: {item_url}", style="red")
                continue
            if d < cutoff:
                print(f":date: Reached date cutoff of {cutoff.isoformat()}, quitting", style="bright_black")
                return matches

            body = parsed.get("body_text") or html
            if contains_ttps(body):
                print(f"  :mag: Found page with TTPs -> {item_url}", style="bright_black")
                fields = extract_advisory_fields(body, item_url)
                if fields is not None:
                    fields["date"] = d.isoformat()
                    matches.append(fields)
            else:
                print(f"  :heavy_minus_sign: No TTPs detected -> {item_url}", style="bright_black")

    return matches

def main() -> None:
    matches = scrape()
    output_file = "out.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(matches, f, indent=2)
    print(f"Wrote {len(matches)} matching advisories to {output_file}")


if __name__ == "__main__":
    main()
