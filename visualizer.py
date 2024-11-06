import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

def visualize_data():
    df = pd.read_csv('network_anomalies_report.csv')
    
    # Plotting number of anomalies over time
    plt.figure(figsize=(10, 6))
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df.set_index('timestamp').resample('T').size().plot(legend=False)
    plt.title('Number of Anomalies Over Time')
    plt.xlabel('Time')
    plt.ylabel('Number of Anomalies')
    plt.show()
    
    # Plotting anomaly type distribution
    plt.figure(figsize=(8, 6))
    sns.countplot(y='anomaly_type', data=df)
    plt.title('Distribution of Anomaly Types')
    plt.xlabel('Count')
    plt.ylabel('Anomaly Type')
    plt.show()

if __name__ == "__main__":
    visualize_data()
