"""Unit tests for monitor.py — packet callback routing and flow processing logic."""
 
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
 
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime
 
 
def make_mock_tcp_packet(src_ip='192.168.1.20', dst_ip='192.168.1.10',
                          src_port=54321, dst_port=80, flags='A',
                          window=64240, payload=b'hello'):
    """Helper to build a mock Scapy TCP packet."""
    from scapy.all import IP, TCP, Raw
    pkt = IP(src=src_ip, dst=dst_ip) / TCP(
        sport=src_port,
        dport=dst_port,
        flags=flags,
        window=window,
        dataofs=5
    ) / Raw(load=payload)
    return pkt
 
def make_mock_udp_packet(src_ip='192.168.1.20', dst_ip='192.168.1.10',
                          src_port=54321, dst_port=53):
    """Helper to build a mock Scapy UDP packet."""
    from scapy.all import IP, UDP
    pkt = IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port)
    return pkt
 
 
class TestPacketCallbackFiltering(unittest.TestCase):
 
    @patch('monitor.flow_manager')
    def test_multicast_packet_is_ignored(self, mock_flow_manager):
        """Packets destined for multicast addresses should be dropped before processing."""
        import monitor
        pkt = make_mock_tcp_packet(dst_ip='239.255.255.250')
        monitor.packet_callback(pkt)
        mock_flow_manager.add_packet.assert_not_called()
 
    @patch('monitor.flow_manager')
    def test_broadcast_packet_is_ignored(self, mock_flow_manager):
        """Packets destined for 255.255.255.255 should be dropped."""
        import monitor
        pkt = make_mock_tcp_packet(dst_ip='255.255.255.255')
        monitor.packet_callback(pkt)
        mock_flow_manager.add_packet.assert_not_called()
 
    @patch('monitor.flow_manager')
    def test_link_local_packet_is_ignored(self, mock_flow_manager):
        """Packets destined for 169.254.x.x should be dropped."""
        import monitor
        pkt = make_mock_tcp_packet(dst_ip='169.254.1.1')
        monitor.packet_callback(pkt)
        mock_flow_manager.add_packet.assert_not_called()
 
    @patch('monitor.flow_manager')
    def test_valid_tcp_packet_passed_to_flow_manager(self, mock_flow_manager):
        """A valid TCP packet should be passed to the flow manager."""
        import monitor
        mock_flow_manager.add_packet.return_value = None  # No completed flow
        pkt = make_mock_tcp_packet()
        monitor.packet_callback(pkt)
        mock_flow_manager.add_packet.assert_called_once()
 
    @patch('monitor.flow_manager')
    def test_udp_packet_passed_to_flow_manager(self, mock_flow_manager):
        """A valid UDP packet should be passed to the flow manager."""
        import monitor
        mock_flow_manager.add_packet.return_value = None
        pkt = make_mock_udp_packet()
        monitor.packet_callback(pkt)
        mock_flow_manager.add_packet.assert_called_once()
 
  
if __name__ == '__main__':
    unittest.main(verbosity=2)