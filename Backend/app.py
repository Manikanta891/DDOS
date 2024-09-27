from scapy.all import *
import pandas as pd
from scapy.layers.http import HTTP
from scapy.layers.dns import DNS
from scapy.layers.ntp import NTP
from scapy.layers.inet import TCP, UDP, IP
from scapy.layers.l2 import ARP
from scapy.layers.inet import ICMP
import pickle
import tkinter as tk
from tkinter import messagebox

from flask import Flask, jsonify
from flask_cors import CORS
import warnings

app = Flask(__name__)
CORS(app) 

warnings.simplefilter(action='ignore', category=pd.errors.SettingWithCopyWarning)

model_path = "C:\\Users\\Manikanta\\OneDrive\\Desktop\\Test Jupyter\\ML_model_sih24\\Normal_TCP.pkl"
with open(model_path, 'rb') as f:
    ml_model = pickle.load(f)

# Function to extract required fields from each packet
def extract_fields(packet, first_timestamp):
    fields = {
        'Source IP': None,
        'Source Port': None,
        'Destination IP': None,
        'Destination Port': None,
        'Protocol': None,
        'Protocol Header Length': None,
        'Total Length': None,
        'Identification': None,
        'Time to Live': None,
        'Time': None,  # Relative time
        'Sequence Number': 0,  # Default to 0 if not present
        'Acknowledgment Number': 0,  # Default to 0 if not present
        'Payload Length': None,
        'Segment Size': None,
        'SYN': 0,
        'ACK': 0,
        'RST': 0,
        'FIN': 0,
        'SYN+ACK': 0,
        'RST+FIN': 0,
        'SYN+RST': 0,
        'DNS Query': 0,
        'HTTP Request': 0,
        'NTP': 0,
        'ARP': 0,
        'ICMP': 0,
        'UDP': 0,
        'SMTP': 0,  # Added SMTP field
        'Frame Length': None  # Added field
    }

    # IP Layer
    if IP in packet:
        ip = packet[IP]
        fields['Source IP'] = ip.src
        fields['Destination IP'] = ip.dst
        fields['Time to Live'] = ip.ttl
        fields['Identification'] = ip.id
        fields['Total Length'] = ip.len
        fields['Protocol Header Length'] = ip.ihl * 4  # IP header length in bytes
        fields['Frame Length'] = ip.len  # Frame length is the total length

        # Set the timestamp
        timestamp = packet.time if hasattr(packet, 'time') else None
        if timestamp is not None:
            fields['Time'] = timestamp - first_timestamp  # Relative time

        # Transport Layer
        if TCP in packet:
            tcp = packet[TCP]
            fields['Source Port'] = tcp.sport
            fields['Destination Port'] = tcp.dport
            fields['Sequence Number'] = tcp.seq if hasattr(tcp, 'seq') else 0
            fields['Acknowledgment Number'] = tcp.ack if hasattr(tcp, 'ack') else 0
            fields['Segment Size'] = len(tcp.payload)
            fields['SYN'] = 1 if tcp.flags & 0x02 else 0
            fields['ACK'] = 1 if tcp.flags & 0x10 else 0
            fields['RST'] = 1 if tcp.flags & 0x04 else 0
            fields['FIN'] = 1 if tcp.flags & 0x01 else 0
            fields['SYN+ACK'] = 1 if (tcp.flags & 0x02) and (tcp.flags & 0x10) else 0
            fields['RST+FIN'] = 1 if (tcp.flags & 0x04) and (tcp.flags & 0x01) else 0
            fields['SYN+RST'] = 1 if (tcp.flags & 0x02) and (tcp.flags & 0x04) else 0

            # SMTP Detection
            if tcp.sport in [25, 465, 587] or tcp.dport in [25, 465, 587]:
                fields['SMTP'] = 1

        elif UDP in packet:
            udp = packet[UDP]
            fields['Source Port'] = udp.sport
            fields['Destination Port'] = udp.dport
            fields['Segment Size'] = len(udp.payload)
            fields['UDP'] = 1
        elif ICMP in packet:
            icmp = packet[ICMP]
            fields['Segment Size'] = len(icmp.payload)
            fields['ICMP'] = 1
        
        # Payload Length
        fields['Payload Length'] = len(packet.payload)
        
        # Protocol Type
        if UDP in packet:
            fields['Protocol'] = 'UDP'
        elif TCP in packet:
            fields['Protocol'] = 'TCP'
        elif ICMP in packet:
            fields['Protocol'] = 'ICMP'
        elif ARP in packet:
            fields['Protocol'] = 'ARP'
            fields['ARP'] = 1
        else:
            fields['Protocol'] = 'Other'
        
        # Protocol Specific Fields
        if DNS in packet:
            fields['DNS Query'] = 1
        if HTTP in packet:
            fields['HTTP Request'] = 1
        if NTP in packet:
            fields['NTP'] = 1

    return fields

# Capture live traffic for 2 seconds
def capture_live_traffic(duration=5):
    try:
        print(f"Capturing live traffic for {duration} seconds...")
        packets = sniff(iface='Wi-Fi', timeout=duration)
        if not packets:
            print("No packets captured.")
            return pd.DataFrame()  # Return an empty DataFrame if no packets are captured

        first_timestamp = packets[0].time  # Timestamp of the first packet
        data = [extract_fields(packet, first_timestamp) for packet in packets]
        return pd.DataFrame(data)
    except Exception as e:
        print(f"An error occurred during live traffic capture: {e}")
        return pd.DataFrame()

def clean_data(df):
    return df.dropna()

def extract_features(df1):
    df1.loc[:, 'session_id'] = (df1['Source IP'].astype(str) + ':' +
                            df1['Source Port'].astype(str) + '-' +
                            df1['Destination IP'].astype(str) + ':' +
                            df1['Destination Port'].astype(str))


    df1.loc[:, 'reversed_session_id'] = (df1['Destination IP'].astype(str) + ':' +
                                     df1['Destination Port'].astype(str) + '-' +
                                     df1['Source IP'].astype(str) + ':' +
                                     df1['Source Port'].astype(str))


    def function1():
        """
        Identifies unique session IDs and calculates the unique source IP count for the entire dataset.
        """
        # Calculate the count of each source IP in the entire dataset
        ip_count = df1.groupby('Source IP')['Source IP'].transform('count')

        # Add the count as a new column for the unique source IPs
        df1.loc[:, 'unq_src_ip_addr'] = ip_count

        # Return unique sessions with relevant fields
        unique_sessions = df1[['session_id', 'reversed_session_id', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol', 'unq_src_ip_addr']].drop_duplicates()
        
        return unique_sessions

    def function2(session_df):
        """
        Calculate the various protocol flags and metrics like source/destination packets, bytes, and frame lengths.
        """
        # Vectorized flag counts
        syn_count = session_df['SYN'].sum()
        ack_count = session_df['ACK'].sum()
        fin_count = session_df['FIN'].sum()
        rst_count = session_df['RST'].sum()
        syn_ack_count = session_df['SYN+ACK'].sum()
        rst_fin_count = session_df['RST+FIN'].sum()
        syn_rst_count = session_df['SYN+RST'].sum()

        # Source packets and bytes
        source_packets = session_df.shape[0]
        source_bytes = session_df['Frame Length'].sum()

        # Protocol-specific metrics
        header_length = session_df['Protocol Header Length'].sum()
        total_length = session_df['Total Length'].sum()
        identification = session_df['Identification'].sum()
        ttl = session_df['Time to Live'].sum()
        seq_num = session_df['Sequence Number'].sum()
        ack_num = session_df['Acknowledgment Number'].sum()
        payload_length = session_df['Payload Length'].sum()
        segment_size = session_df['Segment Size'].sum()

        # Counts for additional fields
        dns_query_count = session_df['DNS Query'].sum()
        http_request_count = session_df['HTTP Request'].sum()
        ntp_count = session_df['NTP'].sum()
        arp_count = session_df['ARP'].sum()
        icmp_count = session_df['ICMP'].sum()
        udp_count = session_df['UDP'].sum()
        smtp_count = session_df['SMTP'].sum()

        return (syn_count, ack_count, fin_count, rst_count, syn_ack_count, rst_fin_count, syn_rst_count,
                source_packets, source_bytes, header_length, total_length, identification, ttl,
                seq_num, ack_num, payload_length, segment_size, dns_query_count, http_request_count,
                ntp_count, arp_count, icmp_count, udp_count, smtp_count)

    def calculate_metrics(session_id, reversed_session_id, unq_src_ip_addr,src_ip):
        """
        Calculate metrics for both normal and reversed session IDs, including Frame Length.
        """
        # Filter data for session_id and reversed_session_id for the entire dataset
        session_df = df1[df1['session_id'] == session_id]
        
        reversed_session_df = df1[df1['session_id'] == reversed_session_id]

        # Calculate metrics for normal session
        metrics = function2(session_df)
        
        # Destination packets and bytes for reversed session
        destination_packets = reversed_session_df.shape[0] if not session_df.empty else 0
        destination_bytes = session_df['Frame Length'].sum() if not session_df.empty else 0

        # Calculate session duration
        session_end_time = df1[df1['session_id'] == session_id]['Time'].max()
        session_duration = session_end_time - df1[df1['session_id'] == session_id]['Time'].min()

        return {
            'src_ip':src_ip,
            'syn_count': metrics[0],
            'ack_count': metrics[1],
            'fin_count': metrics[2],
            'rst_count': metrics[3],
            'syn_ack_count': metrics[4],
            'rst_fin_count': metrics[5],
            'syn_rst_count': metrics[6],
            'source_packets': metrics[7],
            'destination_packets': destination_packets,
            'source_bytes': metrics[8],
            'destination_bytes': destination_bytes,
            'header_length': metrics[9],
            'total_length': metrics[10],
            'identification': metrics[11],
            'ttl': metrics[12],
            'seq_num': metrics[13],
            'ack_num': metrics[14],
            'payload_length': metrics[15],
            'segment_size': metrics[16],
            'dns_query_count': metrics[17],
            'http_request_count': metrics[18],
            'ntp_count': metrics[19],
            'arp_count': metrics[20],
            'icmp_count': metrics[21],
            'udp_count': metrics[22],
            'smtp_count': metrics[23],
            'frame_length': session_df['Frame Length'].sum(),  # Add frame length here
            'session_duration': session_duration,
            'unq_src_ip_addr': unq_src_ip_addr,  # Include unique source IP count
        }

    # Main Loop to Process the Entire Dataset
    df2 = function1()
    
    results=[]

    for _, row in df2.iterrows():
        session_id = row['session_id']
        reversed_session_id = row['reversed_session_id']
        unq_src_ip_addr = row['unq_src_ip_addr']  # Get unique source IP address count
        src_ip= row['Source IP']
        metrics = calculate_metrics(session_id, reversed_session_id, unq_src_ip_addr,src_ip)
        results.append(metrics)

    return pd.DataFrame(results)

# Predict and display traffic analysis result
def predict_and_display(df):
    predictions = ml_model.predict(df.drop(columns=['src_ip']))
    df['prediction'] = predictions
    
    # Count occurrences for each attack type
    normal_count = int(sum(predictions == 0))
    DoS_count = int(sum(predictions == 1))
    DDoS_count = int(sum(predictions == 2))
    DDoS_Bot_count = int(sum(predictions == 3))

    # Get unique source IPs for each type of attack
    Normal_ips=df[df['prediction'] == 0]['src_ip'].unique()
    DoS_ips = df[df['prediction'] == 1]['src_ip'].unique()
    DDoS_ips = df[df['prediction'] == 2]['src_ip'].unique()
    DDoS_Bot_ips = df[df['prediction'] == 3]['src_ip'].unique()

    # Prepare the result as a dictionary
    result = {
        "Normal Traffic Count": normal_count,
        "DoS Attack Count": DoS_count,
        "DDoS Attack Count": DDoS_count,
        "DDoS Bot Traffic Count": DDoS_Bot_count,
        "Normal IPs": Normal_ips.tolist() if Normal_ips.size > 0 else [],
        "DoS IPs": DoS_ips.tolist() if DoS_ips.size > 0 else [],  # Return empty list if no IPs found
        "DDoS IPs": DDoS_ips.tolist() if DDoS_ips.size > 0 else [],
        "DDoS Bot IPs": DDoS_Bot_ips.tolist() if DDoS_Bot_ips.size > 0 else []
    }
    
    return result

@app.route('/api/detect_ddos', methods=['GET'])
def run_detection():
    df = capture_live_traffic(duration=5)
    df_clean = clean_data(df)
    df_features = extract_features(df_clean)
    result_data = predict_and_display(df_features)
    return jsonify(result_data)

if __name__ == "__main__":
    app.run(debug=True, port=5000)