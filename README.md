# knock-knock

This project implements [port knocking](https://en.wikipedia.org/wiki/Port_knocking) 
for Unix-based systems, but does it with a twist. Instead of allowing the user 
to statically define a port combination, it uses a time-based one-time-password (TOTP) to
generate the port-combination. And just as TOTP codes change every 30 seconds, 
the port-combo also changes every 30 seconds. Since there's only 1,000,000 TOTP values 
there's also support for an optional PIN to prevent pre-calculating all 1 million 
port combinations.

The project supports multiple clients, so each client can have their own TOTP secret 
and PIN.

For now the server app must be run as root. There's a `sudo` option in the config,
which enabled the app to be run as non-root user,
but the change from UFW log monitoring to tcpdump broke that feature.

## Python requirements
- pyotp : Python's One-Time-Password package
- qrcode
- python-dateutil

## System requirements:
- Only tested on Ubuntu 24.04, but "probably" works on any reasonably 
modern Debian-based Linux distro.
- `tcpdump` must be installed
- `ufw` (uncomplicated firewall) must be installed and enabled


### Some Additional Background

The project was originally implemented to use the UFW logging to detect 
port knocks, i.e., port 23845 received UDP packet of length X from source IP a.b.c.d.
This worked great in a test environment but worked terribly in a production environment 
that's exposed to the outside world. The problem is, UFW is aggressive about not logging 
too much traffic and so port knocks were frequently not being logged. This forced a 
rewrite of that part of the code and instead (at least for now) I resorted monitoring 
output from tcpdump tcpdump (because it sees packets before they get to the iptables 
rules). Ultimately, it would be preferable to use a libpcap library instead tcpdump 
but that's further off, if ever.