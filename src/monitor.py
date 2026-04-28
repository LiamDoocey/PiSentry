"""Main module for the network monitor. Captures packets and passes them to the flow manager, 
which tracks active flows and extracts features when flows are completed or expired."""

from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
from flow import FlowManager
from features import extract_features
from predict import Predictor
from alerts import AlertManager
from threat_intel import ThreatIntel
from dashboard import add_traffic_event, start_dashboard, set_alert_manager
import threading 
import time
import argparse
import socket

from dotenv import load_dotenv
load_dotenv()

#Init managers
flow_manager = FlowManager()
predictor = Predictor()
alert_manager = None # Set at startup via command line args after AlertManager is initialized
threat_intel = ThreatIntel()

#Color codes for terminal output
RED = '\033[91m'
RESET = '\033[0m'

def packet_callback(packet):
    
    """Called for each packet captured by scapy.
      Extracts flow info and passes it to the flow manager."""

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        size = len(packet)

        #Filter out multicast, broadcast, and link-local traffic which is generally not relevant.
        if(dst_ip.startswith('239.')or 
            dst_ip.startswith('234.')or
            dst_ip.startswith('169.254.') or
            dst_ip == '255.255.255.255'):
            return
        
        timestamp = datetime.fromtimestamp(float(packet.time))
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags

            window = packet[TCP].window
            payload_size = len(packet[TCP].payload)
            header_size = packet[TCP].dataofs * 4

            #Add packet to the flow manager and check if the flow is completed (FIN/RST)
            completed = flow_manager.add_packet(
                src_ip, dst_ip, src_port, dst_port, protocol, size, flags, 
                timestamp = timestamp, 
                window = window,
                payload_size = payload_size,
                header_size = header_size
            )

            #If the flow is completed, extract features
            if completed:
                #Heuristic: If it's a server response flow, mark as benign without ML prediction since it's likely a response to a client request and less likely to be malicious.
                if completed.src_port < 1024:
                    add_traffic_event('OK', 'BENIGN', completed.src_ip, completed.dst_ip, completed.src_port, completed.dst_port, 'TCP', 100.0)
                else:
                    features = extract_features(completed, completed.dst_port)

                    #Layer 1: Check threat intelligence before ML prediction for faster detection of reported threats and to provide additional context in alerts.
                    intel = threat_intel.check_flow(src_ip, dst_ip)
                    if intel['is_threat']:
                        print(f"{RED}[ALERT] Threat detected in flow: {src_ip} -> {dst_ip}")
                        print(f"Source IP: {src_ip} | Destination IP: {dst_ip} | Source Port: {src_port} | Destination Port: {dst_port} | Protocol: {protocol} | Size: {size} bytes")
                        print(f"Threat Intel - Source IP: {intel['src_ip_info']} | Destination IP: {intel['dst_ip_info']}{RESET}")

                        if alert_manager.send_alert(
                            label='THREAT_INTEL_MATCH',
                            confidence=intel['src_ip_info']['abuse_score'] if intel['src_ip_info'] else intel['dst_ip_info']['abuse_score'],
                            src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port, protocol=protocol
                        ):
                            add_traffic_event('THREAT_INTEL_MATCH', 'THREAT_INTEL_MATCH',
                                src_ip, dst_ip, src_port, dst_port, 'TCP',
                                intel['src_ip_info']['abuse_score'] if intel['src_ip_info'] else intel['dst_ip_info']['abuse_score'])
                        return

                    label, confidence = predictor.predict(features)
                
                    #Layer 2: Use ML prediction to detect novel or unknown attacks based on flow features. 
                    # This allows us to catch threats from sources that may not be in the threat intelligence databases yet.
                    if predictor.is_attack(label):
                        print(f"{RED}[ALERT] Attack detected: {label} with {confidence:.2f}% confidence")
                        print(f"Flow: {completed.src_ip}:{completed.src_port} -> {completed.dst_ip}:{completed.dst_port} | Protocol: TCP | Size: {size} bytes{RESET}")
                        predictor.explain(features, label)

                        alerted = alert_manager.send_alert(label, confidence, completed.src_ip, completed.dst_ip, completed.src_port, completed.dst_port, 'TCP')

                        if alerted:
                            add_traffic_event('ALERT', label, completed.src_ip, completed.dst_ip, completed.src_port, completed.dst_port, 'TCP', confidence)
                        else:
                            # If the alert was suppressed due to rate limiting, we can still log it in the dashboard with a special label to indicate it was detected but not alerted.
                            add_traffic_event('ALERT_SUPPRESSED', label, completed.src_ip, completed.dst_ip, completed.src_port, completed.dst_port, 'TCP', confidence)
                    else:
                        print(f"[OK] Benign flow: {completed.src_ip}:{completed.src_port} -> {completed.dst_ip}:{completed.dst_port}")
                        add_traffic_event('OK', 'BENIGN', completed.src_ip, completed.dst_ip, completed.src_port, completed.dst_port, protocol, confidence)
    

        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            
            #UDP has no FIN/RST, so flows are completed based on timeout.
            flow_manager.add_packet(
                src_ip, dst_ip, src_port, dst_port, protocol, size
            )

def expire_flows_periodically():

    """Runs in a separate thread to periodically check for flows inactive outside the timeout threshold.
      When expired flows are found, features are extracted and printed."""
    
    while True:
        time.sleep(10)
        expired = flow_manager.expire_flows()
        for flow in expired:
            if flow.packets:
                
                proto = 'UDP' if flow.protocol == 17 else 'TCP'
            
                #Heuristic: If it's a server response flow, mark as benign without ML prediction since it's likely a response to a client request and less likely to be malicious.
                if flow.dst_port >= 1024 and flow.src_port < 1024:
                    print(f"[OK] Server response flow: {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port}")
                    add_traffic_event('OK', 'BENIGN', flow.src_ip, flow.dst_ip,
                                     flow.src_port, flow.dst_port, proto, 100.0)
                    continue

                features = extract_features(flow, flow.dst_port)

                #Layer 1: Check threat intelligence before ML prediction for faster detection of known threats and to provide additional context in alerts.
                intel = threat_intel.check_flow(flow.src_ip, flow.dst_ip)
                if intel['is_threat']:
                    print(f"{RED}[ALERT] Threat detected in flow: {flow.src_ip} -> {flow.dst_ip}")
                    print(f"Source IP: {flow.src_ip} | Destination IP: {flow.dst_ip} | Source Port: {flow.src_port} | Destination Port: {flow.dst_port} | Protocol: {proto}")
                    print(f"Threat Intel - Source IP: {intel['src_ip_info']} | Destination IP: {intel['dst_ip_info']}{RESET}")

                    if alert_manager.send_alert(
                        label='THREAT_INTEL_MATCH',
                        confidence=intel['src_ip_info']['abuse_score'] if intel['src_ip_info'] else intel['dst_ip_info']['abuse_score'],
                        src_ip=flow.src_ip, dst_ip=flow.dst_ip, src_port=flow.src_port, dst_port=flow.dst_port, protocol=proto
                    ):
                        add_traffic_event('THREAT_INTEL_MATCH', 'THREAT_INTEL_MATCH',
                            flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, proto,
                            intel['src_ip_info']['abuse_score'] if intel['src_ip_info'] else intel['dst_ip_info']['abuse_score'])
                    continue

                #Layer 2: Use ML prediction to detect novel or unknown attacks based on flow features. 
                label, confidence = predictor.predict(features)
                if predictor.is_attack(label):
                    print(f"{RED}[ALERT] Attack detected: {label} with {confidence:.2f}% confidence")
                    print(f"Flow: {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} | Protocol: {proto}{RESET}")
                    predictor.explain(features, label)

                    if alert_manager.send_alert(label, confidence, flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, proto):
                        add_traffic_event('ALERT', label, flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, proto, confidence)
                else:
                    print(f"[OK] Benign flow: {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port}")
                    add_traffic_event('OK', 'BENIGN', flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, proto, confidence)


def start_monitor(interface = None):

    """Starts the network monitor by initializing the flow manager, starting the expiry thread, and beginning packet capture on the default
    interface if none is specified."""

    print("Starting network monitor...")

    #Start thread to periodically check for expired flows and extract features from them.
    expiry_thread = threading.Thread(
        target = expire_flows_periodically,
        daemon = True
    )
    expiry_thread.start()

    #Get the IP address of the machine running the NIDS to filter out its own traffic from the capture, which can reduce noise and improve performance.
    nids_ip = socket.gethostbyname(socket.gethostname())

    #Start sniffing packets. prn calls packet_callback for each captured packet.
    sniff(
        iface =  interface,
        prn = packet_callback,
        store = False,
        filter = f"not dst host {nids_ip}"
    )

if __name__ == "__main__":
    #Parse command line arguments for interface selection and test mode, which allows running the monitor without sending actual alerts for testing and development.
    parser = argparse.ArgumentParser()
    parser.add_argument('--iface', type = str, help = 'Choose what interface to listen on', default = None)
    parser.add_argument('--test', action = 'store_true', help = 'Run in test mode - Alerts wont be actually be sent')
    args = parser.parse_args()

    #Initialize the alert manager and set it for use in the dashboard and monitor.
    alert_manager = AlertManager(test_mode = args.test)
    set_alert_manager(alert_manager)

    #Start the dashboard in a separate thread so it can run concurrently with the packet capture and flow monitoring.
    dashboard_thread = threading.Thread(
        target = start_dashboard,
        daemon = True
    )
    dashboard_thread.start()

    start_monitor(interface = args.iface)