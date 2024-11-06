import sqlite3
import pandas as pd

def generate_report():
    conn = sqlite3.connect('network_anomalies.db')
    df = pd.read_sql_query("SELECT * FROM anomalies", conn)
    conn.close()
    
    # Save report as a CSV file
    df.to_csv('network_anomalies_report.csv', index=False)
    print("Report generated: network_anomalies_report.csv")

if __name__ == "__main__":
    generate_report()
