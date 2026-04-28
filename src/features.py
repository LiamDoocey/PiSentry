"""Extracts features from completed flows to match the features found in the CIC-IDS-2017 dataset, 
including packet counts, byte counts, inter-arrival times, TCP flags, etc."""

import numpy as np

def extract_features(flow, dst_port):
    
    """Extracts CIC-IDS-2017 features from a completed flow object.
    Returns a list of features in the same order as the dataset for use in the ML model."""

    packets = flow.packets
    fwd = flow.fwd_packets
    bwd = flow.bwd_packets
    duration = flow.duration()
    duration_seconds = duration / 1e6 #Convert microseconds to seconds for rate calculations

    #Use [0] for empty lists to avoid issues with empty sequence errors
    fwd_sizes = [p['payload_size'] for p in packets if p['direction'] == 'fwd'] or [0]
    bwd_sizes = [p['payload_size'] for p in packets if p['direction'] == 'bwd'] or [0]
    all_sizes = [p['payload_size'] for p in packets] or [0]

    #----- Inter arrival times ------
    #Time between consevutive packets in microseconds to match CIC-IDS-2017 format
    timestamps = [p['timestamp'] for p in packets]
    iats = [(timestamps[i + 1] - timestamps[i]).total_seconds() * 1e6
            for i in range(len(timestamps) - 1)] if len(timestamps) > 1 else [0]
    
    #Directional IATs for forward and backward packets
    fwd_timestamps = [p['timestamp'] for p in packets if p['direction'] == 'fwd']
    bwd_timestamps = [p['timestamp'] for p in packets if p['direction'] == 'bwd']

    fwd_iats = [(fwd_timestamps[i + 1] - fwd_timestamps[i]).total_seconds() * 1e6
                for i in range(len(fwd_timestamps) - 1)] if len(fwd_timestamps) > 1 else [0]

    bwd_iats = [(bwd_timestamps[i + 1] - bwd_timestamps[i]).total_seconds() * 1e6
                for i in range(len(bwd_timestamps) - 1)] if len(bwd_timestamps) > 1 else [0]
    
    #----- TCP Flags -----
    #Flags are seperated into directions to match the CIC-IDS-2017 features, but also combined for overall flag counts.
    fwd_flags = [p['flags'] for p in packets if p['direction'] == 'fwd' and p['flags']]
    bwd_flags = [p['flags'] for p in packets if p['direction'] == 'bwd' and p['flags']]
    all_flags = fwd_flags + bwd_flags

    #----- Initial Window Size -----
    # Capture the TCP window size from the first pure SYN packet in each direction.
    # SYN-ACK packets are excluded to match CIC-IDS-2017 dataset.
    init_win_fwd = 0
    init_win_bwd = 0

    for p in packets:
        if p['flags'] and 'S' in str(p['flags']) and 'A' not in str(p['flags']):
            if p['direction'] == 'fwd' and init_win_fwd == 0:
                init_win_fwd = p.get('window', 0)
            elif p['direction'] == 'bwd' and init_win_bwd == 0:
                init_win_bwd = p.get('window', 0)


    #----- Header Lengths -----
    #CIC-IDS-2017 includes features for total header length in each direction, as well as the minimum segment size in the forward direction.
    first_fwd_header = min(p.get('header_size', 20) for p in packets if p['direction'] == 'fwd') if any(p['direction'] == 'fwd' for p in packets) else 0

    #Header size is not always available, so we default to 20 bytes (typical TCP header size) if not provided in the packet data.
    fwd_header_total = sum(p.get('header_size', 20) for p in packets if p['direction'] == 'fwd')
    bwd_header_total = sum(p.get('header_size', 20) for p in packets if p['direction'] == 'bwd')

    def count_flag(flag_list, flag):

        """Counts the number of packets with a specific TCP flag set in the provided list of flags."""

        return sum(1 for f in flag_list if flag in str(f))
    
    def safe_div(a, b):

        """Performs safe division, returning 0 if the denominator is 0 to avoid division errors."""

        return a / b if b != 0 else 0
    
    # ----- Feature List -----
    #Order must match the order of features in the CIC-IDS-2017 dataset for correct mapping to the ML model (print(list(X_train.columns)))
    
    features = [
        dst_port,                                   # Destination Port
        duration,                                   # Flow Duration
        len(fwd),                                   # Total Fwd Packets
        len(bwd),                                   # Total Backward Packets
        sum(fwd_sizes),                             # Total Length of Fwd Packets
        sum(bwd_sizes),                             # Total Length of Bwd Packets
        max(fwd_sizes),                             # Fwd Packet Length Max
        min(fwd_sizes),                             # Fwd Packet Length Min
        np.mean(fwd_sizes),                         # Fwd Packet Length Mean
        np.std(fwd_sizes),                          # Fwd Packet Length Std
        max(bwd_sizes),                             # Bwd Packet Length Max
        min(bwd_sizes),                             # Bwd Packet Length Min
        np.mean(bwd_sizes),                         # Bwd Packet Length Mean
        np.std(bwd_sizes),                          # Bwd Packet Length Std
        safe_div(sum(all_sizes), duration_seconds), # Flow Bytes/s
        safe_div(len(packets), duration_seconds),   # Flow Packets/s
        np.mean(iats),                              # Flow IAT Mean
        np.std(iats),                               # Flow IAT Std
        max(iats),                                  # Flow IAT Max
        min(iats),                                  # Flow IAT Min
        sum(fwd_iats),                              # Fwd IAT Total
        np.mean(fwd_iats),                          # Fwd IAT Mean
        np.std(fwd_iats),                           # Fwd IAT Std
        max(fwd_iats),                              # Fwd IAT Max
        min(fwd_iats),                              # Fwd IAT Min
        sum(bwd_iats),                              # Bwd IAT Total
        np.mean(bwd_iats),                          # Bwd IAT Mean
        np.std(bwd_iats),                           # Bwd IAT Std
        max(bwd_iats),                              # Bwd IAT Max
        min(bwd_iats),                              # Bwd IAT Min
        count_flag(fwd_flags, 'P'),                 # Fwd PSH Flags
        count_flag(fwd_flags, 'U'),                 # Fwd URG Flags
        fwd_header_total,                           # Fwd Header Length
        bwd_header_total,                           # Bwd Header Length
        safe_div(len(fwd), duration_seconds),       # Fwd Packets/s
        safe_div(len(bwd), duration_seconds),       # Bwd Packets/s
        min(all_sizes),                             # Min Packet Length
        max(all_sizes),                             # Max Packet Length
        np.mean(all_sizes),                         # Packet Length Mean
        np.std(all_sizes),                          # Packet Length Std
        np.var(all_sizes),                          # Packet Length Variance
        count_flag(all_flags, 'F'),                 # FIN Flag Count
        count_flag(fwd_flags, 'S'),                 # SYN Flag Count
        count_flag(all_flags, 'R'),                 # RST Flag Count
        count_flag(all_flags, 'P'),                 # PSH Flag Count
        count_flag(all_flags, 'A'),                 # ACK Flag Count
        count_flag(all_flags, 'U'),                 # URG Flag Count
        count_flag(all_flags, 'C'),                 # CWE Flag Count
        count_flag(all_flags, 'E'),                 # ECE Flag Count
        int(safe_div(len(bwd), len(fwd))),          # Down/Up Ratio
        np.mean(all_sizes),                         # Average Packet Size
        np.mean(fwd_sizes),                         # Avg Fwd Segment Size
        np.mean(bwd_sizes),                         # Avg Bwd Segment Size
        fwd_header_total,                           # Fwd Header Length.1 (duplicate in dataset)
        len(fwd),                                   # Subflow Fwd Packets
        sum(fwd_sizes),                             # Subflow Fwd Bytes
        len(bwd),                                   # Subflow Bwd Packets
        sum(bwd_sizes),                             # Subflow Bwd Bytes
        init_win_fwd,                               # Init_Win_bytes_forward
        init_win_bwd,                               # Init_Win_bytes_backward
        len([p for p in fwd_sizes if p > 0]),       # act_data_pkt_fwd
        first_fwd_header,                           # min_seg_size_forward
        np.mean(iats),                              # Active Mean
        np.std(iats),                               # Active Std
        max(iats),                                  # Active Max
        min(iats),                                  # Active Min
        np.mean(iats),                              # Idle Mean
        np.std(iats),                               # Idle Std
        max(iats),                                  # Idle Max
        min(iats),                                  # Idle Min
    ]

    return features