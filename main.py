import os
import requests
from playwright.sync_api import sync_playwright

OPENROUTER_KEY = os.environ.get("OPENROUTER_KEY")
OPENROUTER_MODEL = "openrouter/free"
WEB_APP_URL = os.environ.get("GAS_WEB_APP_URL")

def run_pipeline():
    response = requests.get(WEB_APP_URL)
    if response.status_code != 200:
        print("Failed to fetch data from Google Sheet bridge.")
        return
    
    rows = response.json().get("rows", [])
    if not rows:
        print("No pending rows found.")
        return

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1400, "height": 1600})

        processed = 0
        for row in rows:
            if processed >= 20:
                break

            row_index = row["rowIndex"]
            raw_domain = row["domain"]
            company_name = row.get("company", raw_domain)

            domain = str(raw_domain).strip().lower().replace("https://", "").replace("http://", "").replace("www.", "").split("/")[0]
            if not domain:
                continue

            print(f"Processing Row {row_index}: {domain}")

            try:
                # 1. DNS Check via Google DNS over HTTPS
                dns_url = f"https://dns.google/resolve?name=_mta-sts.{domain}&type=TXT"
                dns_res = requests.get(dns_url, timeout=10).json()
                has_mta_sts = False
                if dns_res.get("Answer"):
                    has_mta_sts = any("v=STSv1" in ans.get("data", "") for ans in dns_res["Answer"])

                if has_mta_sts:
                    update_sheet(row_index, "Audited", "Record Found", "N/A", "No Draft Needed")
                else:
                    # 2. Capture cropped EasyDMARC screenshot using Playwright
                    target_url = f"https://easydmarc.com/tools/mta-sts-check?domain={domain}"
                    page.goto(target_url, timeout=40000)
                    page.wait_for_timeout(6000)
                    
                    screenshot_path = f"/tmp/{domain}.jpg"
                    page.screenshot(path=screenshot_path, type="jpeg", quality=80, clip={"x": 0, "y": 450, "width": 1400, "height": 950})

                    # 3. Generate AI Copy via OpenRouter (Exact RMRC Prompt structure)
                    target_company = company_name or domain
                    prompt = (
                        f"Act as a cybersecurity researcher reporting a security vulnerability to the team at {target_company}.\n"
                        f"Generate the email text following this EXACT structure and formatting without any subject line:\n\n"
                        f"Vulnerable Domain: {domain}\n"
                        f"Vulnerability Description:\n"
                        f"Upon examining the DNS (Domain Name System) record, I realized that the MTA-STS record is missing. The MTA-STS mechanism is designed to enforce secure email communication by requiring the use of TLS (Transport Layer Security) encryption. However, in this case, the absence of the MTA-STS record exposes the email infrastructure to potential security vulnerabilities.\n\n"
                        f"Expected Behaviour:\n"
                        f"The MTA-STS record should be correctly configured and published in the DNS records for the domain {domain}. It is essential for secure email communication and enforcing TLS encryption for all incoming and outgoing email traffic.\n\n"
                        f"Proof of Concept:\n"
                        f"Audit Proof Screenshot Attached.\n\n"
                        f"Impact:\n\n"
                        f"* Email Security Risk: Without an MTA-STS record, the domain is vulnerable to man-in-the-middle (MITM) attacks, where email traffic can be intercepted or altered in transit.\n"
                        f"* Email Deliverability Issues: Some mail servers may reject or mark emails as suspicious if they cannot verify the secure connection using MTA-STS.\n"
                        f"* Non-compliance: Domains without MTA-STS records may not comply with modern email security best practices, which could affect the trustworthiness of the domain.\n\n"
                        f"Mitigation:\n\n"
                        f"* Please make sure the DNS configuration for the domain includes the MTA-STS policy. This can be done by adding a DNS TXT record for the domain (e.g., _mta-sts.{domain}), specifying the MTA-STS policy.\n"
                        f"* Enable HTTPS for MTA-STS Reports: Set up a reporting URL for MTA-STS to receive reports about issues with MTA-STS validation.\n"
                        f"* Monitor Email Security: Regularly check the status of the MTA-STS record to ensure it is configured correctly and functioning as intended.\n"
                        f"* DNS Propagation: After setting up the MTA-STS record, verify that DNS changes have been propagated and are accessible from external sources.\n\n"
                        f"Additional Notes:\n\n"
                        f"* MTA-STS provides an additional layer of email security by enforcing TLS encryption between mail servers. It is highly recommended for domains handling sensitive communications.\n"
                        f"I hope this issue will be taken care of quickly, and I would appreciate it if you could let me know the compensation you are offering for this security disclosure."
                    )

                    ai_res = requests.post(
                        "https://openrouter.ai/api/v1/chat/completions",
                        headers={"Authorization": f"Bearer {OPENROUTER_KEY}"},
                        json={"model": OPENROUTER_MODEL, "messages": [{"role": "user", "content": prompt}]},
                        timeout=30
                    ).json()

                    update_sheet(row_index, "Audited", "No Record Found", "GitHub Automation Proof", "Yes")
                    processed += 1

            except Exception as e:
                print(f"Error on {domain}: {str(e)}")
                update_sheet(row_index, "Error", str(e), "", "")

        browser.close()

def update_sheet(row_index, status, findings, link, draft):
    payload = {
        "rowIndex": row_index,
        "status": status,
        "findings": findings,
        "link": link,
        "draft": draft
    }
    requests.post(WEB_APP_URL, json=payload, timeout=10)

if __name__ == "__main__":
    run_pipeline()
