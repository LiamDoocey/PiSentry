import requests
import os
import json
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

class ThreatIntel:
    def __init__(self, cache_file = 'threat_intel_cache.json', cache_hours = 24):

        """Initializes the ThreatIntel class by loading the cache from disk and setting the cache expiration time."""

        self.api_key = os.getenv('ABUSEIPDB_API_KEY')

        if not self.api_key:
            raise ValueError("ABUSEIPDB_API_KEY environment variable not set.")
        
        self.cache_file = cache_file
        self.cache_hours = cache_hours
        self.cache = self._load_cache()

        # RFC 1918 private address ranges and special addresses that should never be checked against the threat intelligence API
        self.private_ip_ranges = [
            '192.168.','10.','172.16.', '172.17.',
            '172.18.', '172.19.', '172.20.', '172.21.',
            '172.22.', '172.23.', '172.24.', '172.25.', 
            '172.26.', '172.27.', '172.28.', '172.29.', 
            '172.30.', '172.31.', '127.', '169.254.'
        ]

    def _load_cache(self):

        """Loads the threat intelligence cache from a local JSON file. If the file doesn't exist, returns an empty dictionary."""

        if os.path.exists(self.cache_file):
            with open(self.cache_file, 'r') as f:
                return json.load(f)
        return {}
    
    def _save_cache(self):

        """Saves the current threat intelligence cache to a local JSON file to persist it across sessions."""

        with open(self.cache_file, 'w') as f:
            json.dump(self.cache, f)

    def _is_private_ip(self, ip):

        """Checks if an IP address is in a private range. Private IPs are not checked against the threat intelligence database."""

        return any(ip.startswith(range) for range in self.private_ip_ranges)
    
    def _is_cache_valid(self, ip):

        """Checks if the cached result for an IP address is still valid based on the cache expiration time."""

        if ip not in self.cache:
            return False
        
        cached_time = datetime.fromisoformat(self.cache[ip]['timestamp'])
        expiry = cached_time + timedelta(hours = self.cache_hours)

        return datetime.now() < expiry
    
    def check_ip(self, ip):

        """Checks an IP address against the AbuseIPDB API and returns a result indicating if it's malicious along with additional info.
        Results are cached to avoid redundant API calls for the same IP within the cache expiration time. Private IPs are skipped."""

        #Skips private IPs
        if self._is_private_ip(ip):
            return None
        
        #Return cached result if IP is in cache and still valid
        if self._is_cache_valid(ip):
            return self.cache[ip]['result']
        
        try:
            response = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers = {
                    'Key': self.api_key,
                    'Accept': 'application/json'
                },
                params = {
                    'ipAddress': ip,
                    'maxAgeInDays': 90 #Only consider reports from the last 90 days to ensure relevance
                }
            )

            if response.status_code == 200:
                data = response.json()['data']

                result = {
                    #Return as malicious if abuse score is 50 or higher
                    'is_malicious': data['abuseConfidenceScore'] >= 50,
                    'abuse_score': data['abuseConfidenceScore'],
                    'country': data.get('countryCode', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                }

                #Store result in cache with timestamp
                self.cache[ip] = {
                    'timestamp': datetime.now().isoformat(),
                    'result': result
                }
                self._save_cache()

                return result
            else:
                print(f"Error checking IP {ip}: {response.status_code} - {response.text}")
                return None
            
        except Exception as e:
            print(f"Exception occurred while checking IP {ip}: {e}")
            return None
        
    def check_flow(self, src_ip, dst_ip):

        """Checks both the source and destination IPs of a flow against the threat intelligence database and returns a combined result."""

        src_result = self.check_ip(src_ip)
        dst_result = self.check_ip(dst_ip)

        is_threat = (
            (src_result and src_result['is_malicious']) or
            (dst_result and dst_result['is_malicious'])
        )

        return {
            'is_threat': is_threat,
            'src_ip_info': src_result,
            'dst_ip_info': dst_result
        }