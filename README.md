RSTconn
-------

A TCPKill is a utility that implements a **TCP reset attack** for IPv4 and IPv6 written in python and scapy.

RESET is a flag in TCP packets to indicate that the connection is not longer working.
If any of the two participants in a TCP connection send a packet
contains such a RESET flag, the connection will be closed immediately.

Thus it can be use to attack TCP connections once the attacker can forge
TCP packets from any of the two parties if he or she know their IPs, ports
and the sequence number of current TCP connection.

The attack can be used to make certain users to fail to use certain
network services based on TCP if we know the information above.

In practice, we should eavesdrop the victims’ communications to get
their IPs, ports and the sequence number.

You can do it by filtering the TCP packets and find the newest packets that we want to attack.

We can sends a TCP packet with RESET flag and the IPs and ports of
source and destination are sniffed from victims. What’s more, the
sequence number will increase in TCP communication, its value should
be equal or lager than the ack value from the lastest packet the sender
received and in the window of receiver. So we should update it.
To ensure successful, we can send lots of packets with different
sequence number which is larger than the sniffed ack field.

Setup
-----

````
pip install rstconn
````

Usage
-----

````
rstconn kills network connections.

optional arguments:
  -h, --help            show this help message and exit
  --iface {lo,enp0s25,lxcbr0,docker0,br-d316e57def52,vethd4f41f0,veth6fa5336, ...}, -i {...}
                        Interface where to listen to
  --ip IP, -ip IP       Server IPv4
  --port PORT, -p PORT  Server port
  --packet-count PACKET_COUNT, -pc PACKET_COUNT
                        listen for a maximum of N packets
  --seq-jitter SEQ_JITTER, -sj SEQ_JITTER
                        Set seq_jitter to be non-zero in order to prove to yourself that the
                        sequence number of a RST segment does indeed need to be exactly equal
                        to the last sequence number ACK-ed by the receiver
  --ignore-syn, -is     if a Packet has SYN flag, not sending RST
  --window-size WINDOW_SIZE, -ws WINDOW_SIZE
                        Window size
  -d {CRITICAL,ERROR,WARNING,INFO,DEBUG}, --debug {CRITICAL,ERROR,WARNING,INFO,DEBUG}
                        Debug level, see python logging; defaults to INFO if omitted
  -m, --monitor         Just sniff traffic without sendin RST
  -v, --version         Print version and exit
````

RSTconn listens for the matching connections and than sends a
number of SYN/ACK and RST packets to the client to get the connection be killed.

The number of packets is configurable by `--packet-count`, `--iface` and
`-ip` and `--port` are related to the local server port to be listen on.

````
rstconn -i lo -ip 127.0.0.1 -p 8000 --packet-count 50
````

Demo
----

````
apt install netcat
````

- Setup TCP connection. In one terminal window run `nc -nvl 8000` to set up a server
- In another terminal window run `nc 127.0.0.1 8000` to connect to the server
- In a third window run `rstconn` to run our sniffing program

You should see the sniffing program log some output, send a RST packet, and the nc connection should be broken.

If you want to test rstconn in IPv6, use instead:

- `nc ::1 8000`
- `nc -nvl ::1 8000`
- `rstconn -i lo -ip "::1" -p 8000 -pc 33`


Credits
-------

- https://gist.github.com/spinpx/263a2ed86f974a55d35cf6c3a2541dc2
- https://github.com/robert/how-does-a-tcp-reset-attack-work


References
----------

- Watson, P.: Slipping in the Window: TCP Reset attacks. (2004)
