#!/usr/bin/env python3

import argparse
import io
import pyotp
import qrcode
import qrcode.image.svg
import os
import sys

import config
import log


def output_svg(uri, output_file):
    factory = qrcode.image.svg.SvgImage
    img = qrcode.make(uri, image_factory=factory)
    with open(output_file, "xt") as f:
        f.write(img.to_string(encoding='unicode'))


def output_qrcode(uri):
    qr = qrcode.QRCode()
    qr.add_data(uri)
    f = io.StringIO()
    qr.print_ascii(out=f)
    f.seek(0)
    print(f.read())


def setup_totp(client_name):
    print(f"client_name={client_name}")
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=client_name, issuer_name="Port Knock App")
    return secret, uri


def output_config(client_file, name, secret, pin, port, knock_cnt, open_duration):
    with open(client_file, "xt") as f:
        if name:
            f.write(f'name = "{name}"\n')
        f.write(f'secret = "{secret}"\n')
        f.write(f'pin = "{pin}"\n')
        f.write(f'ports = {port}\n')
        f.write(f'knock_cnt = {knock_cnt}\n')
        f.write(f'open_duration = {open_duration}\n')


def main(argv):

    tmp_logger = log.Log("info", False)

    argp = argparse.ArgumentParser(prog='knocklisten',
                                   description='Service that listens for port knocking.')
    argp.add_argument('--config-file',
                      required=False,
                      default="/etc/knockknock/knock.toml",
                      help="Path to global configuration file.")
    argp.add_argument('--client-name',
                      required=False,
                      default=None,
                      help="Name of client. If not defined, file name is used for name.")
    argp.add_argument('--pin',
                      required=False,
                      default="",
                      help="PIN to use with client. Blank means no PIN will be used.")
    argp.add_argument('--knock-cnt',
                      required=False,
                      default=3,
                      help="Number of knocks to use with this client. Default is 3.")
    argp.add_argument('--open-duration',
                      required=False,
                      default=10,
                      help="Number of seconds to keep port(s) open following a successful " + \
                        "knock sequence. Default is 10 seconds.")
    argp.add_argument('--port',
                      required=True,
                      action='append',
                      help="Port/proto to open. This option may be specified multiple times. " + \
                           "Proto is optional. Example values: 22, 22/tcp, 443/tcp")
    argp.add_argument('--qr-fmt',
                      required=False,
                      default="ascii",
                      choices=["ascii", "svg", "all", "none"],
                      help="Format of QR Code output. Possible values are 'ascii', 'svg', " + \
                        "'all' or 'none'. " + \
                        "Ascii is output to terminal, SVG is output to --svg_file option.")
    argp.add_argument('--svg-file',
                      required=False,
                      default="qrcode.svg",
                      help="Name of file to write QR code to in SVG format. Only applicable " + \
                        "--qr_fmt option is set to 'svg'.")
    argp.add_argument('filename',
                      help="Name of file to store this configuration. Do not include " + \
                           "path or extension.")

    args = argp.parse_args()

    # load config
    cfg = config.Config(args.config_file, tmp_logger, False)

    print(f"args={args}")

    if not args.filename.endswith(".toml"):
        args.filename += ".toml"

    cname = args.client_name if args.client_name else os.path.splitext(args.filename)[0]

    secret, totp_uri = setup_totp(cname)

    client_file = os.path.normpath(cfg.listener.client_cfg + "/" + args.filename)
    output_config(client_file, args.client_name, secret, args.pin, 
                  args.port, args.knock_cnt, args.open_duration)

    if args.qr_fmt in ["ascii", "all"]:
        output_qrcode(totp_uri)
    elif args.qr_fmt in ["svg", "all"]:
        output_svg(totp_uri, args.svg_file)



if __name__ == '__main__':
    main(sys.argv)
