from scapy.all import sniff

def packet_handler(pkt):
    # Customize this function to process each packet as needed
    print('Packet: ' + pkt.summary() + '\n')

def main():
    # Sniffing on interface 'en0' and calling packet_handler for each packet
    sniff(iface='Wi-Fi', prn=packet_handler, count=5)

if __name__ == "__main__":
    main()
