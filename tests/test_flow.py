"""Unit tests for flow.py — Flow and FlowManager classes."""
 
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
 
import unittest
from datetime import datetime, timedelta
from flow import Flow, FlowManager
 
 
def make_flow(src_ip='192.168.1.1', dst_ip='192.168.1.2',
              src_port=12345, dst_port=80, protocol=6):
    """Helper to create a Flow object."""
    packet = (src_ip, dst_ip, src_port, dst_port, protocol)
    return Flow(packet, datetime.now())
 
 
class TestFlow(unittest.TestCase):
 
    def test_initial_state(self):
        """Flow should initialise with empty packet lists and correct identifiers."""
        flow = make_flow()
        self.assertEqual(flow.src_ip, '192.168.1.1')
        self.assertEqual(flow.dst_ip, '192.168.1.2')
        self.assertEqual(flow.src_port, 12345)
        self.assertEqual(flow.dst_port, 80)
        self.assertEqual(flow.packets, [])
        self.assertEqual(flow.fwd_packets, [])
        self.assertEqual(flow.bwd_packets, [])
 
    def test_add_forward_packet(self):
        """Forward packets should be added to fwd_packets list."""
        flow = make_flow()
        t = datetime.now()
        flow.add_packet(100, t, 'fwd', payload_size=60, header_size=20)
        self.assertEqual(len(flow.packets), 1)
        self.assertEqual(len(flow.fwd_packets), 1)
        self.assertEqual(len(flow.bwd_packets), 0)
        self.assertEqual(flow.packets[0]['payload_size'], 60)
 
    def test_add_backward_packet(self):
        """Backward packets should be added to bwd_packets list."""
        flow = make_flow()
        t = datetime.now()
        flow.add_packet(200, t, 'bwd', payload_size=150, header_size=20)
        self.assertEqual(len(flow.bwd_packets), 1)
        self.assertEqual(len(flow.fwd_packets), 0)
 
    def test_deduplication_within_1ms(self):
        """Duplicate packets within 1ms with same size and flags should be ignored."""
        flow = make_flow()
        t = datetime.now()
        flow.add_packet(100, t, 'fwd', flags='A', payload_size=60)
        flow.add_packet(100, t, 'fwd', flags='A', payload_size=60)  # duplicate
        self.assertEqual(len(flow.packets), 1)
 
    def test_deduplication_different_size_allowed(self):
        """Packets with same timestamp but different size should both be added."""
        flow = make_flow()
        t = datetime.now()
        flow.add_packet(100, t, 'fwd', flags='A', payload_size=60)
        flow.add_packet(200, t, 'fwd', flags='A', payload_size=150)
        self.assertEqual(len(flow.packets), 2)
 
    def test_deduplication_after_1ms_allowed(self):
        """Packets more than 1ms apart should both be added even if identical."""
        flow = make_flow()
        t1 = datetime.now()
        t2 = t1 + timedelta(milliseconds=2)
        flow.add_packet(100, t1, 'fwd', flags='A', payload_size=60)
        flow.add_packet(100, t2, 'fwd', flags='A', payload_size=60)
        self.assertEqual(len(flow.packets), 2)
 
    def test_last_seen_updated(self):
        """last_seen should update with each new packet."""
        flow = make_flow()
        t1 = datetime.now()
        t2 = t1 + timedelta(seconds=1)
        flow.add_packet(100, t1, 'fwd')
        flow.add_packet(100, t2, 'bwd')
        self.assertEqual(flow.last_seen, t2)
 
    def test_duration_microseconds(self):
        """Duration should return microseconds between first and last packet."""
        flow = make_flow()
        t1 = datetime.now()
        t2 = t1 + timedelta(seconds=1)
        flow.add_packet(100, t1, 'fwd')
        flow.add_packet(100, t2, 'bwd')
        self.assertAlmostEqual(flow.duration(), 1_000_000, delta=100)
 
    def test_is_expired_udp_30s(self):
        """UDP flows should expire after 30 seconds of inactivity."""
        packet = ('1.1.1.1', '2.2.2.2', 1234, 53, 17)
        flow = Flow(packet, datetime.now())
        flow.add_packet(100, datetime.now(), 'fwd')
        future = datetime.now() + timedelta(seconds=31)
        self.assertTrue(flow.is_expired(future))
 
    def test_is_expired_tcp_short_flow_10s(self):
        """TCP flows with <= 2 packets should expire after 10 seconds."""
        flow = make_flow()
        t = datetime.now()
        flow.add_packet(100, t, 'fwd')
        future = t + timedelta(seconds=11)
        self.assertTrue(flow.is_expired(future))
 
    def test_is_expired_tcp_long_flow_120s(self):
        """TCP flows with > 2 packets should expire after 120 seconds."""
        flow = make_flow()
        t = datetime.now()
        for i in range(5):
            flow.add_packet(100, t + timedelta(milliseconds=i*10), 'fwd')
        future = t + timedelta(seconds=121)
        self.assertTrue(flow.is_expired(future))
 
    def test_not_expired_within_timeout(self):
        """Flow should not be expired if within timeout window."""
        flow = make_flow()
        t = datetime.now()
        flow.add_packet(100, t, 'fwd')
        future = t + timedelta(seconds=5)
        self.assertFalse(flow.is_expired(future))
 
    def test_slowloris_heuristic_expires_slow_http(self):
        """Slow HTTP flows to port 80 with < 1 pkt/s over 30s should expire early."""
        flow = make_flow(dst_port=80)
        t = datetime.now()
        # Add 3 packets over 60 seconds = 0.05 pkt/s
        for i in range(3):
            flow.add_packet(100, t + timedelta(seconds=i * 20), 'fwd')
        future = t + timedelta(seconds=61)
        self.assertTrue(flow.is_expired(future))
 
 
class TestFlowManager(unittest.TestCase):
 
    def setUp(self):
        self.fm = FlowManager()
 
    def test_new_flow_created(self):
        """Adding a packet should create a new flow."""
        self.fm.add_packet('1.1.1.1', '2.2.2.2', 1234, 80, 6, 100)
        self.assertEqual(len(self.fm.flows), 1)
 
    def test_bidirectional_same_flow(self):
        """Packets in both directions should map to the same flow."""
        self.fm.add_packet('1.1.1.1', '2.2.2.2', 1234, 80, 6, 100)
        self.fm.add_packet('2.2.2.2', '1.1.1.1', 80, 1234, 6, 200)
        self.assertEqual(len(self.fm.flows), 1)
 
    def test_fin_completes_flow(self):
        """FIN flag should complete the flow and return it."""
        self.fm.add_packet('1.1.1.1', '2.2.2.2', 1234, 80, 6, 100, flags='S')
        self.fm.add_packet('1.1.1.1', '2.2.2.2', 1234, 80, 6, 100, flags='A')
        result = self.fm.add_packet('1.1.1.1', '2.2.2.2', 1234, 80, 6, 60, flags='F')
        self.assertIsNotNone(result)
        self.assertEqual(len(self.fm.flows), 0)
 
    def test_rst_completes_flow(self):
        """RST flag should complete the flow and return it."""
        self.fm.add_packet('1.1.1.1', '2.2.2.2', 1234, 80, 6, 100, flags='S')
        result = self.fm.add_packet('1.1.1.1', '2.2.2.2', 1234, 80, 6, 60, flags='R')
        self.assertIsNotNone(result)
        self.assertEqual(len(self.fm.flows), 0)
 
    def test_rst_without_existing_flow_returns_none(self):
        """RST on a non-existent flow should return None."""
        result = self.fm.add_packet('1.1.1.1', '2.2.2.2', 1234, 80, 6, 60, flags='R')
        self.assertIsNone(result)
 
    def test_normal_packet_returns_none(self):
        """Non-completing packet should return None."""
        result = self.fm.add_packet('1.1.1.1', '2.2.2.2', 1234, 80, 6, 100)
        self.assertIsNone(result)
 
    def test_expire_flows(self):
        """Flows inactive beyond timeout should be returned by expire_flows."""
        t = datetime.now() - timedelta(seconds=200)
        self.fm.add_packet('1.1.1.1', '2.2.2.2', 1234, 80, 6, 100, timestamp=t)
        expired = self.fm.expire_flows()
        self.assertEqual(len(expired), 1)
        self.assertEqual(len(self.fm.flows), 0)
 
    def test_active_flow_not_expired(self):
        """Recently active flows should not be expired."""
        self.fm.add_packet('1.1.1.1', '2.2.2.2', 1234, 80, 6, 100)
        expired = self.fm.expire_flows()
        self.assertEqual(len(expired), 0)
        self.assertEqual(len(self.fm.flows), 1)
 
    def test_two_different_flows(self):
        """Different src/dst pairs should create separate flows."""
        self.fm.add_packet('1.1.1.1', '2.2.2.2', 1234, 80, 6, 100)
        self.fm.add_packet('3.3.3.3', '4.4.4.4', 5678, 22, 6, 100)
        self.assertEqual(len(self.fm.flows), 2)
 
    def test_direction_assigned_correctly(self):
        """First packet direction should be fwd, reverse should be bwd."""
        self.fm.add_packet('1.1.1.1', '2.2.2.2', 1234, 80, 6, 100)
        self.fm.add_packet('2.2.2.2', '1.1.1.1', 80, 1234, 6, 200)
        key = self.fm.get_flow_key('1.1.1.1', '2.2.2.2', 1234, 80, 6)
        flow = self.fm.flows[key]
        directions = [p['direction'] for p in flow.packets]
        self.assertIn('fwd', directions)
        self.assertIn('bwd', directions)
 
 
if __name__ == '__main__':
    unittest.main(verbosity=2)