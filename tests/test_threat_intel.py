"""Unit tests for threat_intel.py — ThreatIntel IP checking and caching logic."""
 
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
 
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
 
 
def make_threat_intel():
    """Helper to create a ThreatIntel instance with a mocked API key and no cache file."""
    with patch.dict(os.environ, {'ABUSEIPDB_API_KEY': 'fake_api_key'}), \
         patch('threat_intel.os.path.exists', return_value=False):
        from threat_intel import ThreatIntel
        ti = ThreatIntel()
        ti.cache = {}
        return ti
 
 
def make_api_response(score=0, country='IE', isp='Test ISP'):
    """Helper to build a mock AbuseIPDB API response."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        'data': {
            'abuseConfidenceScore': score,
            'countryCode': country,
            'isp': isp
        }
    }
    return mock_response
 
 
class TestPrivateIPSkipping(unittest.TestCase):
 
    def test_private_192_168_skipped(self):
        """192.168.x.x addresses should return None without an API call."""
        ti = make_threat_intel()
        with patch('threat_intel.requests.get') as mock_get:
            result = ti.check_ip('192.168.1.100')
            self.assertIsNone(result)
            mock_get.assert_not_called()
 
    def test_private_10_skipped(self):
        """10.x.x.x addresses should return None without an API call."""
        ti = make_threat_intel()
        with patch('threat_intel.requests.get') as mock_get:
            result = ti.check_ip('10.0.0.1')
            self.assertIsNone(result)
            mock_get.assert_not_called()
 
    def test_loopback_skipped(self):
        """127.x.x.x loopback addresses should return None without an API call."""
        ti = make_threat_intel()
        with patch('threat_intel.requests.get') as mock_get:
            result = ti.check_ip('127.0.0.1')
            self.assertIsNone(result)
            mock_get.assert_not_called()
 
 
class TestCaching(unittest.TestCase):
 
    def test_cache_hit_skips_api_call(self):
        """A cached IP within the expiry window should not trigger an API call."""
        ti = make_threat_intel()
        ti.cache['8.8.8.8'] = {
            'timestamp': datetime.now().isoformat(),
            'result': {'is_malicious': False, 'abuse_score': 0, 'country': 'US', 'isp': 'Google'}
        }
 
        with patch('threat_intel.requests.get') as mock_get:
            result = ti.check_ip('8.8.8.8')
            mock_get.assert_not_called()
            self.assertFalse(result['is_malicious'])
 
    def test_expired_cache_triggers_api_call(self):
        """A cached result older than 24 hours should trigger a fresh API call."""
        ti = make_threat_intel()
        old_time = (datetime.now() - timedelta(hours=25)).isoformat()
        ti.cache['8.8.8.8'] = {
            'timestamp': old_time,
            'result': {'is_malicious': False, 'abuse_score': 0, 'country': 'US', 'isp': 'Google'}
        }
 
        with patch('threat_intel.requests.get', return_value=make_api_response(score=0)) as mock_get, patch.object(ti, '_save_cache'):
            ti.check_ip('8.8.8.8')
            mock_get.assert_called_once()
 
    def test_api_result_is_cached(self):
        """A fresh API result should be stored in the cache."""
        ti = make_threat_intel()
 
        with patch('threat_intel.requests.get', return_value=make_api_response(score=10)), \
             patch.object(ti, '_save_cache'):
            ti.check_ip('1.2.3.4')
            self.assertIn('1.2.3.4', ti.cache)
 
 
class TestMaliciousScoring(unittest.TestCase):
 
    def test_score_above_50_is_malicious(self):
        """An abuse score of 50 or above should be flagged as malicious."""
        ti = make_threat_intel()
 
        with patch('threat_intel.requests.get', return_value=make_api_response(score=75)), \
             patch.object(ti, '_save_cache'):
            result = ti.check_ip('1.2.3.4')
            self.assertTrue(result['is_malicious'])
            self.assertEqual(result['abuse_score'], 75)
 
    def test_score_exactly_50_is_malicious(self):
        """An abuse score of exactly 50 should be flagged as malicious."""
        ti = make_threat_intel()
 
        with patch('threat_intel.requests.get', return_value=make_api_response(score=50)), \
             patch.object(ti, '_save_cache'):
            result = ti.check_ip('1.2.3.4')
            self.assertTrue(result['is_malicious'])
 
    def test_score_below_50_is_not_malicious(self):
        """An abuse score below 50 should not be flagged as malicious."""
        ti = make_threat_intel()
 
        with patch('threat_intel.requests.get', return_value=make_api_response(score=20)), \
             patch.object(ti, '_save_cache'):
            result = ti.check_ip('8.8.8.8')
            self.assertFalse(result['is_malicious'])
 
 
class TestCheckFlow(unittest.TestCase):
 
    def test_malicious_src_ip_flags_flow(self):
        """A flow with a malicious source IP should be flagged as a threat."""
        ti = make_threat_intel()
 
        with patch.object(ti, 'check_ip', side_effect=[
            {'is_malicious': True, 'abuse_score': 95, 'country': 'CN', 'isp': 'BadISP'},
            {'is_malicious': False, 'abuse_score': 0, 'country': 'IE', 'isp': 'Eir'}
        ]):
            result = ti.check_flow('1.2.3.4', '192.168.1.10')
            self.assertTrue(result['is_threat'])
 
    def test_malicious_dst_ip_flags_flow(self):
        """A flow with a malicious destination IP should be flagged as a threat."""
        ti = make_threat_intel()
 
        with patch.object(ti, 'check_ip', side_effect=[
            {'is_malicious': False, 'abuse_score': 0, 'country': 'IE', 'isp': 'Eir'},
            {'is_malicious': True, 'abuse_score': 80, 'country': 'RU', 'isp': 'BadISP'}
        ]):
            result = ti.check_flow('192.168.1.20', '5.6.7.8')
            self.assertTrue(result['is_threat'])
 
    def test_clean_flow_not_flagged(self):
        """A flow where both IPs are clean should not be flagged as a threat."""
        ti = make_threat_intel()
 
        with patch.object(ti, 'check_ip', side_effect=[
            {'is_malicious': False, 'abuse_score': 5, 'country': 'IE', 'isp': 'Eir'},
            {'is_malicious': False, 'abuse_score': 0, 'country': 'US', 'isp': 'Google'}
        ]):
            result = ti.check_flow('192.168.1.20', '8.8.8.8')
            self.assertFalse(result['is_threat'])
 
    def test_private_ips_in_flow_not_flagged(self):
        """A flow between two private IPs should not be flagged as a threat."""
        ti = make_threat_intel()
 
        with patch.object(ti, 'check_ip', return_value=None):
            result = ti.check_flow('192.168.1.20', '192.168.1.10')
            self.assertFalse(result['is_threat'])
 
 
if __name__ == '__main__':
    unittest.main(verbosity=2)