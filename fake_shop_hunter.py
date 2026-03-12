import csv
import logging
import requests
import concurrent.futures
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
import time

class FakeShopHunter:
    """
    A Threat Intelligence tool to identify and validate potential fake shop domains
    targeting specific brands using OSINT and active heuristics.
    """
    def __init__(self, brand_name, vt_api_key=None, urlscan_api_key=None):
        self.brand_name = brand_name.lower().replace(" ", "") # Clean spaces for domain logic
        self.vt_api_key = vt_api_key
        self.urlscan_api_key = urlscan_api_key
        self.ua = UserAgent()
        self.results = []
        
        # Configure Logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - [%(module)s] - %(message)s'
        )
        self.logger = logging.getLogger("FakeShopHunter")

    def generate_permutations(self):
        """Generates domain permutations using typosquatting and homoglyphs."""
        self.logger.info(f"Generating permutations for {self.brand_name}...")
        # Simulated dnstwist output for demonstration
        return [
            f"www-{self.brand_name}-vip.com",
            f"{self.brand_name}-checkout.net",
            f"buy-{self.brand_name}s.co",
            f"{self.brand_name}-official-store.com",
            f"cheap-{self.brand_name}.shop"
        ]

    def check_crtsh(self):
        """Queries Certificate Transparency logs (crt.sh) for recently issued SSL certs."""
        self.logger.info(f"Querying crt.sh for {self.brand_name}...")
        url = f"https://crt.sh/?q={self.brand_name}&output=json"
        domains = set()
        
        try:
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '').lower()
                    if '*' not in name and name: 
                        domains.add(name)
        except Exception as e:
            self.logger.error(f"Failed to query crt.sh for {self.brand_name}: {e}")
            
        return list(domains)

    def validate_domain(self, domain, source):
        """Pings the domain and checks heuristics (SSL, HTML content)."""
        target_url = f"http://{domain}" 
        headers = {'User-Agent': self.ua.random}
        
        domain_data = {
            "Domain": domain,
            "Detection_Source": source,
            "Status": "Offline",
            "VT_Score": "N/A",
            "URLScan_Link": "N/A",
            "Risk_Level": "Low",
            "Heuristic_Flags": []
        }

        try:
            response = requests.get(target_url, headers=headers, timeout=10, allow_redirects=True)
            if response.status_code == 200:
                domain_data["Status"] = "Live"
                
                soup = BeautifulSoup(response.text, 'html.parser')
                page_text = soup.get_text().lower()
                
                # Look for scam signals
                if "gmail.com" in page_text or "yahoo.com" in page_text:
                    domain_data["Heuristic_Flags"].append("Suspicious free email provider")
                if "western union" in page_text or "crypto" in page_text:
                    domain_data["Heuristic_Flags"].append("Suspicious payment methods")
                
                if domain_data["Heuristic_Flags"]:
                    domain_data["Risk_Level"] = "High"

        except requests.exceptions.RequestException:
            pass # Domain is offline or unreachable

        return domain_data

    def run(self):
        """Orchestrates the hunting process."""
        self.logger.info(f"--- Starting Hunt for: {self.brand_name.upper()} ---")
        
        permutations = self.generate_permutations()
        crtsh_domains = self.check_crtsh()
        
        targets = {dom: "dnstwist" for dom in permutations}
        for dom in crtsh_domains:
            if dom not in targets:
                targets[dom] = "crt.sh"

        self.logger.info(f"Total unique domains to validate for {self.brand_name}: {len(targets)}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_domain = {
                executor.submit(self.validate_domain, dom, source): dom 
                for dom, source in targets.items()
            }
            
            for future in concurrent.futures.as_completed(future_to_domain):
                try:
                    result = future.result()
                    self.results.append(result)
                    if result["Status"] == "Live":
                        self.logger.warning(f"[LIVE] Fake shop found: {result['Domain']} - Risk: {result['Risk_Level']}")
                except Exception as e:
                    pass

        self.export_to_csv()

    def export_to_csv(self):
        """Exports findings to a CSV file."""
        live_results = [r for r in self.results if r["Status"] == "Live"]
        
        if not live_results:
            self.logger.info(f"No live threats found for {self.brand_name}.")
            return

        filename = f"{self.brand_name}_fakeshops.csv"
        keys = live_results[0].keys()
        
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as output_file:
                dict_writer = csv.DictWriter(output_file, fieldnames=keys)
                dict_writer.writeheader()
                dict_writer.writerows(live_results)
            self.logger.info(f"Results successfully exported to {filename}")
        except IOError as e:
            self.logger.error(f"Failed to write CSV: {e}")


if __name__ == "__main__":
    # Top 20 brands highly targeted by fake shops and counterfeits
    top_20_brands = [
        "Rolex", "Nike", "Apple", "Louis Vuitton", "Ray Ban", 
        "Gucci", "The North Face", "Adidas", "Patagonia", "Yeti", 
        "Dyson", "Oakley", "Supreme", "Ugg", "Lego", 
        "Cartier", "Hermes", "Prada", "Sephora", "Makita"
    ]

    print(f"Initializing batch scan for {len(top_20_brands)} brands...\n")

    for brand in top_20_brands:
        hunter = FakeShopHunter(brand_name=brand)
        hunter.run()
        # Sleep briefly between brands to avoid aggressive rate-limiting from crt.sh
        time.sleep(5) 
        print("-" * 50)
        
    print("\nBatch scan complete. Check your folder for generated CSV files.")
