from scapy.all import sniff
import csv
import time 
import pandas as pd
import matplotlib.pyplot as plt

# Log dosyasını açıp başlıkları yaz
with open("trafik_log.csv", mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["Timestamp", "IP Source", "IP Destination", "Source Port", "Destination Port", "Protocol", "Packet Size"])

def yakala(paket):
    if paket.haslayer('IP') and paket.haslayer('TCP'):
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        
        # Paket bilgilerini CSV'ye yaz
        with open("trafik_log.csv", mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([
                timestamp,
                paket['IP'].src,
                paket['IP'].dst,
                paket['TCP'].sport,
                paket['TCP'].dport,
                "TCP",
                len(paket)  # Paket boyutunu kaydet
            ])

print("Sniffer başlatıldı. Trafik dinleniyor.")
sniff(filter="tcp", prn=yakala, store=0)

# CSV dosyasını Pandas ile oku
df = pd.read_csv("trafik_log.csv")

print(df.head())  # İlk 5 satır

# Paket boyutlarını grafikle gösterme????
if 'Packet Size' in df.columns:
    df['Packet Size'].plot(kind='hist', bins=50, alpha=0.75)
    plt.title('Packet Size Distribution')
    plt.xlabel('Packet Size (bytes)')
    plt.ylabel('Frequency')
    plt.show()
else:
    print("Packet Size sütunu bulunamadı!")
