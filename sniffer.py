from scapy.all import sniff
import csv

def yakala(paket):
    if paket.haslayer('IP') and paket.haslayer('TCP'):
        with open("trafik_log.csv", mode='a') as file:
            writer = csv.writer(file)
            writer.writerow([paket['IP'].src, paket['IP'].dst, paket['TCP'].sport, paket['TCP'].dport])

print("Sniffer başlatıldı. Trafik dinleniyor.")
sniff(filter="tcp port 80", prn=yakala, store=0)

