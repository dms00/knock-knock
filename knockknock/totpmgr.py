
import knockutil as kutil
import pyotp
import time
from datetime import datetime


class TotpMgr:

    # knock_data:
    #    {'start_epoch': 0, totp': '', 'ports': [0,...], 'lens': [0,...]}

    def __init__(self, clicfg, knock_expiration, logger):
        self.logger = logger
        self.pin = clicfg.pin
        self.port_cnt = clicfg.knock_cnt
        self.pytotp = pyotp.TOTP(clicfg.secret)
        self.knock_data = {'start_epoch': 0, 'expiration': 0, 'totp': '', 
                           'cnt': 0, 'ports': [], 'lens': []}
        self.old_knock_data = {'start_epoch': 0, 'expiration': 0, 'totp': '', 
                               'cnt': 0, 'ports': [], 'lens': []}
        # epoch is time self.totp was set. Use this to determine if it's time
        # to get a new totp
        self.totp_epoch = 0
        self.totp = ''
        self.curr_epoch = 0
        self.knock_expiration = knock_expiration
        self.totp_now()
        self.rotate_totp()

    def totp_now(self):
        self.curr_epoch = int(time.time())
        curr_totp_age = datetime.now().second % 30
        our_totp_age = self.curr_epoch - self.totp_epoch

        if our_totp_age > curr_totp_age:
            new_totp = self.pytotp.now()
            if new_totp != self.totp:
                self.totp_epoch = self.curr_epoch
                self.totp = new_totp
        
        return self.totp

    def rotate_totp(self):
        self.totp_now()

        if self.totp != self.knock_data['totp']:
            self.old_knock_data = self.knock_data

            self.logger.debug(f"Setup new totp {self.totp}")
            (ports, lens) = kutil.calc_ports_lengths(self.totp, self.pin, self.port_cnt, self.logger)
            self.knock_data = {'start_epoch': self.curr_epoch - 1, # Add 1 second slop
                               'expiration': self.curr_epoch + 35, # 5-ish extra seconds
                               'totp': self.totp,
                               'cnt': self.port_cnt,
                               'ports': ports,
                               'lens': lens}
            self.logger.debug(self.knock_data)
