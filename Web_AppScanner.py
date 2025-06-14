import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Payloads to test for vulnerabilities
sql_load = ["' OR '1'='1", "';--", "' OR 1=1 --"]
xss_load = [
    "<script>alert('XSS')</script>",
    "'><svg/onload=alert(1)>",
    "'\"><iframe src=javascript:alert(1)>"
]

# Track visited links during crawling
viewed_link = set()

# heads to mimic a browser
heads = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

# Extract all forms from a given URL
def get(url):
    try:
        res = requests.get(url, headers=heads, timeout=5)
        soup = BeautifulSoup(res.content, "html.parser")
        return soup.find_all("form")
    except Exception as e:
        print(f"❌ Error fetching forms: {e}")
        return []

# Submit the form with payload data
def submit(form, url, payload):
    action = form.get("action")
    method = form.get("method", "get").lower()
    tar = urljoin(url, action)
    inputs = form.find_all(["input", "textarea", "select"])

    data = {}
    for input_t in inputs:
        name = input_t.get("name")
        input_type = input_t.get("type", "text")
        if name:
            data[name] = payload if input_type != "submit" else "submit"

    try:
        if method == "post":
            return requests.post(tar, data=data, headers=heads, timeout=5)
        else:
            return requests.get(tar, params=data, headers=heads, timeout=5)
    except Exception as e:
        print(f"❌ Form submission error: {e}")
        return None

# Check if payload is reflected in the res
def vulnub(res, payload):
    if res and res.status_code == 200:
        return payload in res.text
    return False

# Scan a specific page for SQLi and XSS
def scan(url):
    print(f"\n🔍 Scanning: {url}")
    forms = get(url)

    if not forms:
        print("⚠️ No forms found.")
        return

    for form in forms:
        print("  📄 Found form:")
        
        # SQL Injection test
        for payload in sql_load:
            res = submit(form, url, payload)
            if vulnub(res, payload):
                print(f"    ⚠️ SQL Injection vulnerability detected with payload: {payload}")
                break

        # XSS test
        for payload in xss_load:
            res = submit(form, url, payload)
            if vulnub(res, payload):
                print(f"    ⚠️ XSS vulnerability detected with payload: {payload}")
                break

# Crawl pages and scan each one
def crawl_and_scan(start_url):
    to_visit = [start_url]

    while to_visit:
        url = to_visit.pop()
        if url in viewed_link:
            continue
        viewed_link.add(url)

        try:
            res = requests.get(url, headers=heads, timeout=5)
            if res.status_code != 200:
                continue
        except:
            continue

        scan(url)

        soup = BeautifulSoup(res.content, "html.parser")
        for link in soup.find_all("a", href=True):
            new_url = urljoin(url, link["href"])
            if start_url in new_url and new_url not in viewed_link:
                to_visit.append(new_url)

# Entry point
if __name__ == "__main__":
    target = input("Enter the target URL (e.g., http://localhost:8000): ").strip()
    crawl_and_scan(target)
