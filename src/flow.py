"""Manages network flows and groups into TCP/UDP sessions, tracks flow state,
 and extracts features when flows are completed or expired."""

from datetime import datetime

class Flow:

    """Represents a single network flow, tracking packets,
      timestamps, and state."""
    
    def __init__(self, packet, timestamp):

        """Initializes a flow with the first packet, setting identifiers and timestamps."""

        #Flow identifiers
        self.src_ip = packet[0]
        self.dst_ip = packet[1]
        self.src_port = packet[2]
        self.dst_port = packet[3]
        self.protocol = packet[4]

        #Packet storage and
        self.packets = [] #All packets in the flow
        self.fwd_packets = [] #Sizes of forward packets (src -> dst)
        self.bwd_packets = [] #Sizes of backward packets (dst -> src)

        #Timestamps and state
        self.start_time = timestamp 
        self.last_seen = timestamp
        self.is_active = True

    def add_packet(self, size, timestamp, direction, flags = None, window = 0, payload_size = 0, header_size = 0):

        """Adds a packet to the flow, updating packet lists, timestamps, and state.
          If TCP flags indicate FIN/RST, marks the flow as completed."""
        
        # if self.packets:

        #     #Check for duplicate packets (same size, flags, and timestamp within 1ms) to avoid inflating packet counts due to duplicates in capture
        #     last = self.packets[-1]
        #     time_diff = abs((timestamp - last['timestamp']).total_seconds())

        #     if time_diff < 0.001 and size == last['size'] and str(flags) == str(last['flags']):
        #         return


        self.packets.append({
            'size': size,
            'timestamp': timestamp,
            'direction': direction,
            'flags': flags,
            'window': window,
            'payload_size': payload_size,
            'header_size': header_size
        })

        #Update forward/backward packet lists based on direction for easier feature extraction
        if direction == 'fwd':
            self.fwd_packets.append(size)
        else:
            self.bwd_packets.append(size)

        self.last_seen = timestamp
        
    def duration(self):

        """Returns flow in microseconds to match CIC-IDS-2017 format."""

        return (self.last_seen - self.start_time).total_seconds() * 1e6
    
    def is_expired(self, current_time, timeout = None):
        
        """Determines if the flow has been inactive for longer than the specified timeout.
          If no timeout is provided, uses default values based on protocol (30s for UDP, 120s for TCP)."""

        if timeout is None:
            if self.protocol == 17:
                timeout = 30
            elif len(self.packets) <= 2:
                timeout = 10
            else:
                timeout = 120

        #Slowloris attack heuristic: If it's an HTTP flow with very low packet rate over a long duration
        if self.dst_port == 80 or self.src_port == 80 and len(self.packets) > 2:
            duration_seconds = (current_time - self.start_time).total_seconds()
            packets_per_second = len(self.packets) / duration_seconds if duration_seconds > 0 else 0
            if packets_per_second < 1.0 and duration_seconds > 30:
                return True
        
        return (current_time - self.last_seen).total_seconds() > timeout
    
class FlowManager:

    """Manages active flows, adding packets to existing flows or creating new ones as needed."""

    def __init__(self):
        self.flows = {} #Active flows indexed by a tuple of (src_ip, dst_ip, src_port, dst_port, protocol)
        self.completed_flows = [] #Flows that have been completed (FIN/RST) or expired, waiting for feature extraction

    def get_flow_key(self, src_ip, dst_ip, src_port, dst_port, protocol):

        """Makes bi-directional flow keys so that packets in either direction map to the same flow."""

        forward = (src_ip, dst_ip, src_port, dst_port, protocol)
        backward = (dst_ip, src_ip, dst_port, src_port, protocol)
        return min(forward, backward)
        
    def add_packet(self, src_ip, dst_ip, src_port, dst_port, protocol, size, flags = None, timestamp = None, window = 0, payload_size = 0, header_size = 0):

        """Adds a packet to the appropriate flow, creating a new flow if necessary.
            If TCP flags indicate FIN/RST, marks the flow as completed and returns it for feature extraction."""

        if timestamp is None:
            timestamp = datetime.now()

        key = self.get_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)

        #Check for TCP FIN/RST flags to determine if the flow is completed
        fin_rst = False
        if flags:
            fin_rst = 'F' in str(flags) or 'R' in str(flags)

        #If FIN/RST is seen but the flow doesn't exist, ignore the packet since it may be an orphaned FIN/RST without a corresponding flow
        if fin_rst and key not in self.flows:
            return None
        
        #Create new flow if it doesn't exist, then add packet to the flow
        if key not in self.flows:
            self.flows[key] = Flow(
                (src_ip, dst_ip, src_port, dst_port, protocol),
                timestamp
            )
        
        flow = self.flows[key]

        #Determine packet direction based on flow identifiers.
        if (src_ip, dst_ip, src_port, dst_port) == (flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port):
            direction = 'fwd'
        else:
            direction = 'bwd'

        flow.add_packet(size, timestamp, direction, flags, window, payload_size, header_size)

        #Complete flow if FIN/RST flags are seen in TCP packets
        if fin_rst:
            self.completed_flows.append(flow)
            del self.flows[key]
            return flow
        
        return None
        
    def expire_flows(self):

        """Checks active flows for expiration based on inactivity and moves expired flows to the completed_flows list for feature extraction.
        Called in the background thread in monitor.py to periodically clean up inactive flows."""

        current_time = datetime.now()
        expired = []

        for key, flow in list(self.flows.items()):
            if flow.is_expired(current_time):
                expired.append(flow)
                del self.flows[key]

        self.completed_flows.extend(expired)
        return expired