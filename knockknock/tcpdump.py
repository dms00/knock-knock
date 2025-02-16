import os
import re
import subprocess
import time
from dateutil.parser import parse

from knockutil import PORT_START, PORT_END
import taillog


class Tcpdump:
    def __init__(self, cfg, logger, timeout=2):
        self.cmd = cfg.tcpdump.cmd
        self.log_file = cfg.tcpdump.log_file
        self.max_line_count = cfg.tcpdump.truncate_size
        self.timeout = timeout
        self.logger = logger
        self.tcpdump_args = [f'{self.cmd}', '-i', 'any', '-l', '-n', '--direction=in', '-s', '63',
                             '--no-promiscuous-mode', 'udp', 'and', 'dst', 'portrange',
                             '{}-{}'.format(PORT_START, PORT_END), 'and', 'not', 'port', 
                             '53', 'and', 'less', '51']

        # Sample input:
        # "00:24:19.604204 eth0  In  IP 108.185.236.147.48367 > 85.90.244.227.56965: UDP, length 16"
        # groups() => ('00:24:19.604204', '108.185.236.147', '56965', '16')
        # groups: timestamp, source ip, dest port, length
        regex_str = r'^([\d:.]+)\s.+\sIn\s+IP\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,5}[\s>]+' \
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\.(\d{1,5}):.+UDP.+length\s+(\d+)'
        self.p = re.compile(regex_str)
        self.process = self.run_tcpdump(self.log_file)
        self.taillog = taillog.TailLog(cfg, logger, self.log_file)


    def run_tcpdump(self, output_file_name):
        self.output_file_name = output_file_name
        self.outfile = open(output_file_name, "w")
        self.logger.debug(f"Starting {self.cmd}, redirecting output to {self.output_file_name}")
        process = subprocess.Popen(self.tcpdump_args, 
                                   stdout=self.outfile, stderr=subprocess.PIPE)

        return process


    def check_truncate(self):
        if self.taillog.current_line_count < self.max_line_count:
            return
        self.logger.debug(f"Truncate output file ({self.output_file_name}) and resetting read/write position.")
        self.outfile.seek(0, os.SEEK_SET)
        self.outfile.truncate(0)
        self.taillog.truncate()


    def match(self, log_line):
        if not log_line:
            return None
        m = self.p.match(log_line)
        if m is None:
            return m
        else:
            self.logger.debug('Groups from line parse: {}'.format(m.groups()))
            return dict(ts=int(parse(m.group(1)).timestamp()), saddr=m.group(2),
                        dport=int(m.group(3)), len=int(m.group(4)))


    def tail(self):
        sleep_duration = 0.33
        sleep_countdown = self.timeout

        while True:
            l = self.taillog.next()
            if l:
                return l
            else:
                self.check_truncate()
                if self.timeout == 0:
                    time.sleep(sleep_duration)
                else:
                    if sleep_countdown <= 0:
                        return None
                    else:
                        time.sleep(sleep_duration)
                        sleep_countdown -= sleep_duration