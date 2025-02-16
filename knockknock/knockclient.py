#!/usr/bin/env python3

import argparse
import os
import socket
import sys
import time

import knockutil
#import pyotp

def get_totp():
    import pyotp
    secret = os.environ.get('KNOCK_SECRET', None)
    if secret is None:
        print("KNOCK_SECRET environment variable not set.", file=sys.stderr)
        return None
    p = pyotp.TOTP(secret)
    return p.now()

def open_udpsocket():
    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def send_knock(sock, ip, port, len):
    msg = bytes(len)
    sock.sendto(msg, (ip, port))


def get_ip(host):
    return socket.gethostbyname(host)


def main(argv):
    print(argv)
    argp = argparse.ArgumentParser(prog='knockclient',
                                   description='Knock to open port(s).')
    argp.add_argument('-p',
                      '--pin', 
                      required=False,
                      default='',
                      help="Pin value.")
    argp.add_argument('--host',
                      required=True,
                      help="Hostname or IP address of host to contact.")
    argp.add_argument('--cnt',
                      required=False,
                      default=3,
                      help="Hostname or IP address of host to contact.")
    argp.add_argument("--otp",
                      required=False,
                      default=None,
                      help="One-time-password. If otp not present, use " \
                        "authenticator key in KNOCK_SECRET environment variable.")

    v = argp.parse_args()
    print(v)

    if v.otp is None:
        v.otp = get_totp()
    ports, lengths = knockutil.calc_ports_lengths(v.otp, v.pin, v.cnt)
    print(f"ports={ports} lengths={lengths}")
    sock = open_udpsocket()
    ip = get_ip(v.host)
    cnt = int(v.cnt)

    for i in range(0, cnt):
        print(f"sending {lengths[i]} bytes to {ports[i]}")
        send_knock(sock, ip, ports[i], lengths[i])
        if i < cnt-1:
            time.sleep(0.5)

if __name__ == '__main__':
    main(sys.argv)
