from scapy.all import *
import sqlite3

conn_W = sqlite3.connect('whitelist_ips.db')
cursor_W = conn_W.cursor()
conn_B = sqlite3.connect('blacklist_ips.db')
cursor_B = conn_B.cursor()
cursor_B.execute('''CREATE TABLE IF NOT EXISTS blacklist_ips(ip TEXT)''')


def handle_packet(packet):
    ip_address = packet[IP].src
    cursor_W.execute("SELECT count(*) FROM whitelist_ips WHERE ip=?", (ip_address,))
    result = cursor_W.fetchone()
    if result[0] == 0:
        cursor_B.execute("INSERT INTO blacklist_ips VALUES (?)", (ip_address,))
        conn_W.commit()
        conn_B.commit()
        print(f"IP {ip_address} is not in the whitelist. Added to the Black_database.")


if __name__ == '__main__':
    sniff(prn=handle_packet, filter="ip", iface="Ether")
