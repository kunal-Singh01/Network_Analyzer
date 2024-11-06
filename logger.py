import sqlite3
from datetime import datetime

def log_anomaly(src_ip, dst_ip, anomaly_type, details):
    conn = sqlite3.connect('network_anomalies.db')
    c = conn.cursor()
    
    c.execute("INSERT INTO anomalies (src_ip, dst_ip, anomaly_type, details) VALUES (?, ?, ?, ?)",
              (src_ip, dst_ip, anomaly_type, details))
    
    conn.commit()
    conn.close()
    print(f"Logged anomaly: {anomaly_type} from {src_ip} to {dst_ip}")

if '__name__' == "__main__":
    # Example usage
    log_anomaly("192.168.1.1", "192.168.1.100", "SYN flood attempt", "SYN packet to 192.168.1.100")
