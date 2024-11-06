import sqlite3

def setup_database():
    conn = sqlite3.connect('network_anomalies.db')
    c = conn.cursor()
    
    # Create anomalies table if it doesn't exist
    c.execute('''CREATE TABLE IF NOT EXISTS anomalies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    src_ip TEXT,
                    dst_ip TEXT,
                    anomaly_type TEXT,
                    details TEXT
                )''')
    
    conn.commit()
    conn.close()

if __name__ == "__main__":
    setup_database()
