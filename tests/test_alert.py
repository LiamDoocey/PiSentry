"""Unit tests for alerts.py — AlertManager SMS alerting and cooldown logic."""
 
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
 
import unittest
from unittest.mock import patch, MagicMock
from alerts import AlertManager
 
 
def make_manager():
    """Helper to create an AlertManager in test mode with mocked SNS and env vars."""
    with patch.dict(os.environ, {
        'AWS_ACCESS_KEY_ID': 'fake_key',
        'AWS_SECRET_KEY': 'fake_secret',
        'SNS_TOPIC_ARN': 'arn:aws:sns:eu-west-1:123456789:test-topic'
    }):
        with patch('alerts.boto3.client'):
            return AlertManager(test_mode=True)
 
 
class TestAlertCooldown(unittest.TestCase):
 
    @patch('alerts.get_cooldown', return_value=None)
    @patch('alerts.set_cooldown')
    def test_first_alert_is_sent(self, mock_set, mock_get):
        """First alert for a given label and IP should always be sent."""
        manager = make_manager()
        result = manager.send_alert(
            label='PortScan',
            confidence=65.0,
            src_ip='192.168.1.20',
            dst_ip='192.168.1.10',
            src_port=54321,
            dst_port=80,
            protocol='TCP'
        )
        self.assertTrue(result)
 
    @patch('alerts.get_cooldown')
    @patch('alerts.set_cooldown')
    def test_duplicate_alert_within_cooldown_is_blocked(self, mock_set, mock_get):
        """A second alert for the same label and IP within 300s should be blocked."""
        from datetime import datetime, timedelta
        # Simulate a cooldown thats 60s old
        mock_get.return_value = datetime.now() - timedelta(seconds=60)
 
        manager = make_manager()
        result = manager.send_alert(
            label='PortScan',
            confidence=65.0,
            src_ip='192.168.1.20',
            dst_ip='192.168.1.10',
            src_port=54321,
            dst_port=80,
            protocol='TCP'
        )
        self.assertFalse(result)
 
    @patch('alerts.get_cooldown')
    @patch('alerts.set_cooldown')
    def test_alert_allowed_after_cooldown_expires(self, mock_set, mock_get):
        """An alert should be sent once the 300s cooldown has expired."""
        from datetime import datetime, timedelta
        # Simulate a cooldown that expired 10 seconds ago
        mock_get.return_value = datetime.now() - timedelta(seconds=310)
 
        manager = make_manager()
        result = manager.send_alert(
            label='SSH-Patator',
            confidence=70.0,
            src_ip='192.168.1.20',
            dst_ip='192.168.1.10',
            src_port=22,
            dst_port=22,
            protocol='TCP'
        )
        self.assertTrue(result)
 
    @patch('alerts.get_cooldown', return_value=None)
    @patch('alerts.set_cooldown')
    def test_different_labels_same_ip_both_sent(self, mock_set, mock_get):
        """Two different attack types from the same IP should both send alerts."""
        manager = make_manager()
 
        result1 = manager.send_alert(
            label='PortScan',
            confidence=60.0,
            src_ip='192.168.1.20',
            dst_ip='192.168.1.10',
            src_port=54321,
            dst_port=80,
            protocol='TCP'
        )
 
        result2 = manager.send_alert(
            label='DDoS',
            confidence=55.0,
            src_ip='192.168.1.20',
            dst_ip='192.168.1.10',
            src_port=54321,
            dst_port=80,
            protocol='TCP'
        )
 
        self.assertTrue(result1)
        self.assertTrue(result2)
 
 
class TestSubscriptions(unittest.TestCase):
 
    @patch('alerts.get_all_subscriptions', return_value={})
    @patch('alerts.save_subscription')
    def test_subscribe_new_number(self, mock_save, mock_get_all):
        """Subscribing a new phone number should return True and save it."""
        manager = make_manager()
        manager.sns.subscribe = MagicMock(return_value={
            'SubscriptionArn': 'arn:aws:sns:eu-west-1:123:test:abc123'
        })
 
        result = manager.subscribe('+353861234567')
        self.assertTrue(result)
        mock_save.assert_called_once()
 
    @patch('alerts.get_all_subscriptions', return_value={'+353861234567': 'arn:aws:sns:eu-west-1:123:test:abc123'})
    def test_subscribe_duplicate_number(self, mock_get_all):
        """Subscribing an already subscribed number should return False."""
        manager = make_manager()
        result = manager.subscribe('+353861234567')
        self.assertFalse(result)
 
    @patch('alerts.get_all_subscriptions', return_value={'+353861234567': 'arn:aws:sns:eu-west-1:123:test:abc123'})
    @patch('alerts.delete_subscription')
    def test_unsubscribe_existing_number(self, mock_delete, mock_get_all):
        """Unsubscribing an existing number should return True and delete it."""
        manager = make_manager()
        manager.sns.unsubscribe = MagicMock()
 
        result = manager.unsubscribe('+353861234567')
        self.assertTrue(result)
        mock_delete.assert_called_once_with('+353861234567')
 
 
if __name__ == '__main__':
    unittest.main(verbosity=2)