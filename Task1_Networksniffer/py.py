from scapy.all import sniff
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6


def inspect_packet(pkt):
    print("\n" + "-" * 45)
    print("Packet Captured")

    # Ethernet Info
    if Ether in pkt:
        e = pkt[Ether]
        print("\n[ Ethernet Frame ]")
        print("SRC MAC :", e.src)
        print("DST MAC :", e.dst)
        print("TYPE    :", hex(e.type))

    # IP Version Check
    if IP in pkt:
        ip = pkt[IP]
        print("\n[ IPv4 Header ]")
        print("SRC IP  :", ip.src)
        print("DST IP  :", ip.dst)
        print("TTL     :", ip.ttl)
        print("PROTO   :", ip.proto)

    elif IPv6 in pkt:
        ip6 = pkt[IPv6]
        print("\n[ IPv6 Header ]")
        print("SRC IP  :", ip6.src)
        print("DST IP  :", ip6.dst)
        print("HOP LIM :", ip6.hlim)
        print("NEXT HDR:", ip6.nh)

    # Transport Layer
    if TCP in pkt:
        tcp = pkt[TCP]
        print("\n[ TCP Segment ]")
        print("SRC PORT:", tcp.sport)
        print("DST PORT:", tcp.dport)
        print("SEQ NUM :", tcp.seq)
        print("ACK NUM :", tcp.ack)
        print("FLAGS   :", tcp.flags)

        data_len = len(tcp.payload)
        if data_len:
            print("PAYLOAD :", data_len, "bytes")

    elif UDP in pkt:
        udp = pkt[UDP]
        print("\n[ UDP Datagram ]")
        print("SRC PORT:", udp.sport)
        print("DST PORT:", udp.dport)
        print("LENGTH  :", udp.len)

    print("\n[ Packet Summary ]")
    print(pkt.summary())
    print("-" * 45)


def start_capture():
    print("Author: Kritira | Packet Sniffer")
    print("Network Sniffer Running")
    print("Use Ctrl+C to stop\n")

    sniff(prn=inspect_packet, store=False)


if __name__ == "__main__":
    start_capture()


# method 2:

#from scapy.all import sniff
#from scapy.layers.l2 import Ether
#from scapy.layers.inet import IP, TCP, UDP
#from scapy.layers.inet6 import IPv6
#from datetime import datetime

# Global packet counter
#packet_count = 0

# Log file
#LOG_FILE = "packet_log.txt"


#def write_log(text):
    #with open(LOG_FILE, "a") as f:
        #f.write(text + "\n")


#def inspect_packet(pkt):
    #global packet_count
   #packet_count += 1

    #timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    #header = f"\nPacket #{packet_count} | Time: {timestamp}"
    #divider = "-" * 60

    #print(header)
    #print(divider)

   # write_log(header)
   # write_log(divider)

    # Ethernet Layer
   # if Ether in pkt:
      #  e = pkt[Ether]
      #  line = f"ETH  | SRC: {e.src}  DST: {e.dst}  TYPE: {hex(e.type)}"
       # print(line)
       # write_log(line)

    # IPv4
    #if IP in pkt:
      #  ip = pkt[IP]
      #  line = f"IPv4 | SRC: {ip.src}  DST: {ip.dst}  TTL: {ip.ttl}"
     #   print(line)
      #  write_log(line)

    # IPv6
   # elif IPv6 in pkt:
       # ip6 = pkt[IPv6]
        #line = f"IPv6 | SRC: {ip6.src}  DST: {ip6.dst}  HOP: {ip6.hlim}"
      #  print(line)
       # write_log(line)

    # TCP
    # if TCP in pkt:
    #     tcp = pkt[TCP]
    #     line = (
    #         f"TCP  | SPORT: {tcp.sport}  DPORT: {tcp.dport}  "
    #         f"SEQ: {tcp.seq}  FLAGS: {tcp.flags}"
    #     )
    #     print(line)
    #     write_log(line)

    #     if len(tcp.payload) > 0:
    #         payload_line = f"DATA | TCP Payload Size: {len(tcp.payload)} bytes"
    #         print(payload_line)
    #         write_log(payload_line)

    # UDP
    # elif UDP in pkt:
    #     udp = pkt[UDP]
    #     line = f"UDP  | SPORT: {udp.sport}  DPORT: {udp.dport}  LEN: {udp.len}"
    #     print(line)
    #     write_log(line)

    # summary = f"SUMMARY: {pkt.summary()}"
    # print(summary)
    # print(divider)

    # write_log(summary)
    # write_log(divider)


#def start_capture():
   # print("Simple Network Sniffer Started")
  #  print("Logging packets to:", LOG_FILE)
  #  print("Press Ctrl+C to stop\n")

    # write_log("=== Packet Capture Started ===")

    # sniff(prn=inspect_packet, store=False)


#if __name__ == "__main__":
   # start_capture()
