from scapy.all import sniff
import csv
import time
import pandas as pd
import matplotlib.pyplot as plt

packet_count = 0  # Yeni: Toplam paket sayacı

# CSV dosyasını oluştur
with open("trafik_log.csv", mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["Timestamp", "IP Source", "IP Destination", "Source Port", "Destination Port", "Protocol", "Packet Size"])

def yakala(paket):
    global packet_count
    if paket.haslayer('IP') and paket.haslayer('TCP'):
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        packet_count += 1

        # Terminale canlı sayaç yazdır
        print(f"\rTCP paketleri yakalanıyor... (Toplam: {packet_count})", end="")

        with open("trafik_log.csv", mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([
                timestamp,
                paket['IP'].src,
                paket['IP'].dst,
                paket['TCP'].sport,
                paket['TCP'].dport,
                "TCP",
                len(paket)
            ])

print("Sniffer başlatıldı.")
sniff(filter="tcp", prn=yakala, store=0)

# CSV dosyasını oku ve histogram göster
df = pd.read_csv("trafik_log.csv")
print("\nİlk 5 veri:\n", df.head())

if 'Packet Size' in df.columns:
    df['Packet Size'].plot(kind='hist', bins=50, alpha=0.75)
    plt.title('Packet Size Distribution')
    plt.xlabel('Packet Size (bytes)')
    plt.ylabel('Frequency')
    plt.show()
else:
    print("Packet Size sütunu bulunamadı!")
