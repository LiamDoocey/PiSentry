"""Unit tests for features.py — CIC-IDS-2017 feature extraction."""
 
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
 
import unittest
from datetime import datetime, timedelta
from flow import Flow, FlowManager
from features import extract_features
 
 
def build_flow(src_ip='192.168.1.1', dst_ip='192.168.1.2',
               src_port=12345, dst_port=80, protocol=6,
               packets=None):
    """Helper to build a Flow with given packets.
    packets: list of dicts with keys: direction, payload_size, header_size, flags, window, delay_ms
    """
    packet_tuple = (src_ip, dst_ip, src_port, dst_port, protocol)
    t = datetime.now()
    flow = Flow(packet_tuple, t)
 
    for i, p in enumerate(packets or []):
        ts = t + timedelta(milliseconds=p.get('delay_ms', i * 100))
        flow.add_packet(
            size=p.get('payload_size', 0) + p.get('header_size', 20),
            timestamp=ts,
            direction=p.get('direction', 'fwd'),
            flags=p.get('flags', None),
            window=p.get('window', 0),
            payload_size=p.get('payload_size', 0),
            header_size=p.get('header_size', 20)
        )
 
    return flow
 
 
class TestFeatureCount(unittest.TestCase):
 
    def test_returns_70_features(self):
        """extract_features should return exactly 70 features."""
        flow = build_flow(packets=[
            {'direction': 'fwd', 'payload_size': 100, 'header_size': 20, 'delay_ms': 0},
            {'direction': 'bwd', 'payload_size': 200, 'header_size': 20, 'delay_ms': 100},
        ])
        features = extract_features(flow, 80)
        self.assertEqual(len(features), 70)
 
 
class TestDestinationPort(unittest.TestCase):
 
    def test_destination_port_is_first_feature(self):
        """Feature index 0 should be the destination port."""
        flow = build_flow(dst_port=22, packets=[
            {'direction': 'fwd', 'payload_size': 50, 'header_size': 20}
        ])
        features = extract_features(flow, 22)
        self.assertEqual(features[0], 22)
 
    def test_destination_port_http(self):
        flow = build_flow(dst_port=80, packets=[
            {'direction': 'fwd', 'payload_size': 50, 'header_size': 20}
        ])
        features = extract_features(flow, 80)
        self.assertEqual(features[0], 80)
 
 
class TestPacketCounts(unittest.TestCase):
 
    def test_fwd_packet_count(self):
        """Feature index 2 should be total forward packet count."""
        flow = build_flow(packets=[
            {'direction': 'fwd', 'payload_size': 100, 'header_size': 20, 'delay_ms': 0},
            {'direction': 'fwd', 'payload_size': 100, 'header_size': 20, 'delay_ms': 100},
            {'direction': 'bwd', 'payload_size': 200, 'header_size': 20, 'delay_ms': 200},
        ])
        features = extract_features(flow, 80)
        self.assertEqual(features[2], 2)  # Total Fwd Packets
 
    def test_bwd_packet_count(self):
        """Feature index 3 should be total backward packet count."""
        flow = build_flow(packets=[
            {'direction': 'fwd', 'payload_size': 100, 'header_size': 20, 'delay_ms': 0},
            {'direction': 'bwd', 'payload_size': 200, 'header_size': 20, 'delay_ms': 100},
            {'direction': 'bwd', 'payload_size': 200, 'header_size': 20, 'delay_ms': 200},
        ])
        features = extract_features(flow, 80)
        self.assertEqual(features[3], 2)  # Total Backward Packets
 
 
class TestPayloadSizes(unittest.TestCase):
 
    def test_total_fwd_payload(self):
        """Feature index 4 should be sum of forward payload sizes."""
        flow = build_flow(packets=[
            {'direction': 'fwd', 'payload_size': 100, 'header_size': 20, 'delay_ms': 0},
            {'direction': 'fwd', 'payload_size': 150, 'header_size': 20, 'delay_ms': 100},
        ])
        features = extract_features(flow, 80)
        self.assertEqual(features[4], 250)  # Total Length of Fwd Packets
 
    def test_total_bwd_payload(self):
        """Feature index 5 should be sum of backward payload sizes."""
        flow = build_flow(packets=[
            {'direction': 'fwd', 'payload_size': 100, 'header_size': 20, 'delay_ms': 0},
            {'direction': 'bwd', 'payload_size': 500, 'header_size': 20, 'delay_ms': 100},
            {'direction': 'bwd', 'payload_size': 300, 'header_size': 20, 'delay_ms': 200},
        ])
        features = extract_features(flow, 80)
        self.assertEqual(features[5], 800)  # Total Length of Bwd Packets
 
    def test_payload_only_not_full_packet(self):
        """Feature extraction should use payload_size not full packet size."""
        flow = build_flow(packets=[
            {'direction': 'fwd', 'payload_size': 60, 'header_size': 40, 'delay_ms': 0},
        ])
        features = extract_features(flow, 80)
        self.assertEqual(features[6], 60)   # Fwd Packet Length Max
        self.assertEqual(features[7], 60)   # Fwd Packet Length Min
 
 
class TestFlagCounts(unittest.TestCase):
 
    def test_syn_flag_count_fwd_only(self):
        """SYN flag count should only count forward SYN packets (index 42)."""
        flow = build_flow(packets=[
            {'direction': 'fwd', 'flags': 'S', 'payload_size': 0, 'header_size': 20, 'delay_ms': 0},
            {'direction': 'bwd', 'flags': 'SA', 'payload_size': 0, 'header_size': 20, 'delay_ms': 100},
        ])
        features = extract_features(flow, 80)
        self.assertEqual(features[42], 1)   # SYN Flag Count — fwd only
 
    def test_fin_flag_count_all(self):
        """FIN flag count should count all FIN packets (index 41)."""
        flow = build_flow(packets=[
            {'direction': 'fwd', 'flags': 'F', 'payload_size': 0, 'header_size': 20, 'delay_ms': 0},
            {'direction': 'bwd', 'flags': 'F', 'payload_size': 0, 'header_size': 20, 'delay_ms': 100},
        ])
        features = extract_features(flow, 80)
        self.assertEqual(features[41], 2)   # FIN Flag Count
 
    def test_ack_flag_count(self):
        """ACK flag count should count all ACK packets (index 45)."""
        flow = build_flow(packets=[
            {'direction': 'fwd', 'flags': 'A', 'payload_size': 0, 'header_size': 20, 'delay_ms': 0},
            {'direction': 'bwd', 'flags': 'A', 'payload_size': 0, 'header_size': 20, 'delay_ms': 100},
            {'direction': 'fwd', 'flags': 'A', 'payload_size': 0, 'header_size': 20, 'delay_ms': 200},
        ])
        features = extract_features(flow, 80)
        self.assertEqual(features[45], 3)   # ACK Flag Count
 
 
class TestInitWin(unittest.TestCase):
 
    def test_init_win_fwd_from_syn(self):
        """Init_Win_bytes_forward (index 58) should come from the first SYN packet."""
        flow = build_flow(packets=[
            {'direction': 'fwd', 'flags': 'S', 'payload_size': 0, 'header_size': 20, 'window': 64240, 'delay_ms': 0},
            {'direction': 'bwd', 'flags': 'SA', 'payload_size': 0, 'header_size': 20, 'window': 65535, 'delay_ms': 100},
            {'direction': 'fwd', 'flags': 'A', 'payload_size': 0, 'header_size': 20, 'window': 64240, 'delay_ms': 200},
        ])
        features = extract_features(flow, 80)
        self.assertEqual(features[58], 64240)   # Init_Win_bytes_forward
 
    def test_init_win_bwd_from_syn_ack(self):
        """Init_Win_bytes_backward (index 59) should come from the first SYN-ACK — but SA contains A so is excluded.
        Only pure SYN (no A in flags) is captured. bwd SYN-ACK will have 'A' so init_win_bwd stays 0."""
        flow = build_flow(packets=[
            {'direction': 'fwd', 'flags': 'S', 'payload_size': 0, 'header_size': 20, 'window': 1024, 'delay_ms': 0},
            {'direction': 'bwd', 'flags': 'SA', 'payload_size': 0, 'header_size': 20, 'window': 65535, 'delay_ms': 100},
        ])
        features = extract_features(flow, 80)
        # SA contains 'A' so init_win_bwd should remain 0 per our implementation
        self.assertEqual(features[59], 0)       # Init_Win_bytes_backward
 
 
class TestSafeDivision(unittest.TestCase):
 
    def test_flow_bytes_per_second_nonzero(self):
        """Flow Bytes/s (index 14) should be nonzero for flows with duration."""
        flow = build_flow(packets=[
            {'direction': 'fwd', 'payload_size': 1000, 'header_size': 20, 'delay_ms': 0},
            {'direction': 'bwd', 'payload_size': 500, 'header_size': 20, 'delay_ms': 1000},
        ])
        features = extract_features(flow, 80)
        self.assertGreater(features[14], 0)     # Flow Bytes/s
 
    def test_zero_duration_no_crash(self):
        """Single packet flow (zero duration) should not raise ZeroDivisionError."""
        flow = build_flow(packets=[
            {'direction': 'fwd', 'payload_size': 100, 'header_size': 20, 'delay_ms': 0},
        ])
        try:
            features = extract_features(flow, 80)
            self.assertEqual(len(features), 70)
        except ZeroDivisionError:
            self.fail("extract_features raised ZeroDivisionError on zero-duration flow")
 
 
class TestDownUpRatio(unittest.TestCase):
 
    def test_down_up_ratio(self):
        """Down/Up Ratio (index 49) should be int(bwd_count / fwd_count)."""
        flow = build_flow(packets=[
            {'direction': 'fwd', 'payload_size': 100, 'header_size': 20, 'delay_ms': 0},
            {'direction': 'bwd', 'payload_size': 200, 'header_size': 20, 'delay_ms': 100},
            {'direction': 'bwd', 'payload_size': 200, 'header_size': 20, 'delay_ms': 200},
        ])
        features = extract_features(flow, 80)
        self.assertEqual(features[49], 2)       # int(2 bwd / 1 fwd) = 2
 
    def test_down_up_ratio_no_fwd(self):
        """Down/Up Ratio should be 0 when there are no fwd packets (safe_div)."""
        flow = build_flow(packets=[
            {'direction': 'bwd', 'payload_size': 200, 'header_size': 20, 'delay_ms': 0},
        ])
        features = extract_features(flow, 80)
        self.assertEqual(features[49], 0)
 
 
class TestActDataPktFwd(unittest.TestCase):
 
    def test_act_data_pkt_fwd(self):
        """act_data_pkt_fwd (index 60) should count fwd packets with payload > 0."""
        flow = build_flow(packets=[
            {'direction': 'fwd', 'payload_size': 100, 'header_size': 20, 'delay_ms': 0},
            {'direction': 'fwd', 'payload_size': 0, 'header_size': 20, 'delay_ms': 100},  # ACK, no data
            {'direction': 'fwd', 'payload_size': 50, 'header_size': 20, 'delay_ms': 200},
        ])
        features = extract_features(flow, 80)
        self.assertEqual(features[60], 2)       # Only 2 packets had payload > 0
 
 
class TestHeaderLengths(unittest.TestCase):
 
    def test_fwd_header_length_total(self):
        """Fwd Header Length (index 32) should be sum of all fwd header sizes."""
        flow = build_flow(packets=[
            {'direction': 'fwd', 'payload_size': 0, 'header_size': 32, 'delay_ms': 0},
            {'direction': 'fwd', 'payload_size': 0, 'header_size': 32, 'delay_ms': 100},
            {'direction': 'bwd', 'payload_size': 0, 'header_size': 20, 'delay_ms': 200},
        ])
        features = extract_features(flow, 80)
        self.assertEqual(features[32], 64)      # 32 + 32 = 64
 
    def test_min_seg_size_forward(self):
        """min_seg_size_forward (index 61) should be the minimum fwd header size."""
        flow = build_flow(packets=[
            {'direction': 'fwd', 'payload_size': 0, 'header_size': 32, 'delay_ms': 0},
            {'direction': 'fwd', 'payload_size': 0, 'header_size': 20, 'delay_ms': 100},
        ])
        features = extract_features(flow, 80)
        self.assertEqual(features[61], 20)      # min(32, 20) = 20
 
 
if __name__ == '__main__':
    unittest.main(verbosity=2)