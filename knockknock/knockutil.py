import hashlib
import sys

Version = '1.0.0'

# Not using the ephemeral ports. Too much traffic. Try to reduce
# work for packet filter
PORT_START = 32768
PORT_END = 32768+0x3fff

def calc_ports_lengths(totp, pin, cnt, logger=None):
    cnt = int(cnt)
    if cnt > 8 or cnt < 1:
        msg = "Count is out of range. Must be between 1 and 8. Setting to default 3."
        if logger:
            logger.warning(msg)
        else:
            print(msg, file=sys.stderr)
        cnt = 3
    
    hash = hashlib.sha1(bytes(pin + totp, 'utf-8')).hexdigest()

    # read cnt lengths from hash (1 hex-digit each)
    lengths = [int(hash[i], 16) for i in range(cnt)]

    # get cnt ports from hash starting at offset 'cnt' (4 hex digits each (16 bits), 
    # but use only 14 bits - max value 16k)
    ports = [(int(hash[i*4+cnt:i*4+cnt+4], 16) & 0x3fff) + PORT_START for i in range(cnt)]

    return (ports, lengths)