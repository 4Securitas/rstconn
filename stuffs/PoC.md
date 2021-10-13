# As stated by the RFC you need to send a FIN segment then wait for the endpoint's acknowledgment (ACK) + FIN segment and then send a last ACK segment for it.

# Here is a simple example using Scapy:

# from scapy.all import *

# conf.L3socket=L3RawSocket

# sport=10000
# dport=45000
# pkt=IP(src="1.2.3.4", dst="4.5.6.7")

# SYN=pkt/TCP(sport=sport, dport=dport, flags="S")
# SYNACK=sr1(SYN)
# ACK=pkt/TCP(sport=sport, dport=dport, flags="A", seq=SYNACK.ack, ack=SYNACK.seq + 1)
# send(ACK)

...

# FIN=pkt/TCP(sport=sport, dport=dport, flags="FA", seq=SYNACK.ack, ack=SYNACK.seq + 1)
# FINACK=sr1(FIN)
# LASTACK=pkt/TCP(sport=sport, dport=dport, flags="A", seq=FINACK.ack, ack=FINACK.seq + 1)
# send(LASTACK)
