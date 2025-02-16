from collections import namedtuple
import glob
#import log
import os
#import sys
#import textwrap
import tomllib


class Config():

    maincfg = {
        'listener': {
            'knock_expiration': 10,
            'pidfile': "/var/run/knock.pid",
            'client_cfg': "/etc/knockknock/conf.d",
            'failopen': True,
            'failopen_ports': ["22/tcp"],
            'failopen_min_time': 60,
        },
        'ufw': {
            'ufw_cmd': "/usr/sbin/ufw",
            'use_sudo': True,
        },
        'logging': {
            'log_level': "info",
            'syslog': False,
        },
        'tcpdump': {
            'log_file': "/tmp/tcpdump-knock.out",
            'cmd': "/usr/bin/tcpdump",
        },
    }
    clicfg = {
        'secret': None,
        'pin': None,
        'name': None,
        'ports': ["22/tcp"],
        'knock_cnt': 3,
        'open_duration': 10,
    }


    def __init__(self, toml_file, logger, load_clients=True):
        self.logger = logger
        self.toml_file = toml_file
        # Set default config values
        self.clients = []
        self.toml_data = self._load_config(self.toml_file)
        self._process_global_config()
        if load_clients:
            self._process_client_configs()
        self.logger = None


    def _load_config(self, toml_file):
        with open(toml_file, "rb") as f:
            data = tomllib.load(f)
        return data


    def _process_global_config(self):
        self.listener = self._process_listener_section()
        self.logging = self._process_main_section('logging')
        self.ufw = self._process_main_section('ufw')
        self.tcpdump = self._process_main_section('tcpdump')


    def _process_main_section(self, section):
        cfg = self.toml_data.get(section, {})
        default = self.maincfg.get(section, {})

        # populate missing config keys with default values
        for k, v in default.items():
            if k not in cfg:
                cfg[k] = v
        Obj = namedtuple(section, ' '.join(cfg.keys()))
        return Obj(**cfg)


    def _process_listener_section(self):
        listener = self._process_main_section('listener')
        if not (1 <= listener.knock_expiration <= 30):
            self.logger.warning("knock_expiration config value out of range. Setting to default 10.")
            listener.knock_expiration = 10

        # convert failopen_ports list from [ 22, "80/tcp", ... ] to 
        # [["22", None], ["80", "tcp"], ...]
        new_list = []
        for item in listener.failopen_ports:
            new_list.append(str(item).split('/'))

        return listener._replace(failopen_ports=new_list)


    def _process_client_configs(self):
        loc = os.path.realpath(self.listener.client_cfg + '/' + '*.toml')
        client_files = glob.glob(loc)

        for f in client_files:

            c = self._load_config(f)
            default = self.clicfg

            if c:
                # Set defaults for undefined configs
                if not c.get('name'):
                    c['name'] = os.path.basename(os.path.splitext(f)[0])

                for k, v in default.items():
                    if k not in c:
                        if v is not None:
                            c[k] = v

                if not (1 <= c['knock_cnt'] <= 8):
                    self.logger.error(f"Invalid client config for '{c['name']}'. " + \
                                       "knock_count out of range. Skipping client.")
                    continue

                ports = []
                for pp in c.get('ports'):
                    # Entry can be port, 22, or port/proto, e.g., 22/tcp
                    # We want to convert this to (22, None) or (22, tcp)
                    l = str(pp).split('/')
                    l[0] = int(l[0])
                    if len(l) == 1:
                        l.append(None)
                    ports.append(l)

                # overwrite ports from ["22/tcp", "53"] to be list of 
                # lists, e.g., [[22,'tcp'], [53,None]]
                c['ports'] = ports
                # self.clients.append(c)
                Obj = namedtuple('client', ' '.join(c.keys()))
                self.clients.append(Obj(**c))
