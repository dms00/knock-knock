
import re
import subprocess
import time


class Firewall:
    def __init__(self, cfg, logger):
        self.logger = logger
        self.base_cmd = [cfg.ufw.ufw_cmd]
        if cfg.ufw.use_sudo:
            self.base_cmd = ['sudo'] + self.base_cmd
        self.rules_present = True
        self.cfg = cfg

        # groups: port/proto, action, from, comment
        self.re_rule = re.compile(r'^(\d+(?:/\w+)?)\s+(\S+)\s+(\S+)\s+#\s*knock\s+(.*)$')
        # There are 2 rules types: allow, fail
        # allow comment regex. groups: type, id, expire
        self.re_cmt_allow = re.compile(r'^\s*type:\s*(\w+)\s+id:\s*(\S+.*)\s+expire:\s*(\d+).*$')
        # failopen comment regex. groups: type, expire
        self.re_cmt_fopen = re.compile(r'^\s*type:\s*(\w+)\s+expire:\s*(\d+).*$')


    def mk_allow_comment(self, id, expire):
        return f"knock type:allow id:{id} expire:{expire}"
    

    def mk_failopen_comment(self):
        expire = int(time.time()) + int(self.cfg.listener.failopen_min_time)
        return f"knock type:fail expire:{expire}"


    def mk_allow_rule(self, src_ip, proto, dest_port, comment):
        if proto:
            return ["allow", "from", src_ip, "proto", proto, "to", "any", 
                    "port", f"{dest_port}", "comment", comment]
        else:
            return ["allow", "from", src_ip, "to", "any", 
                    "port", f"{dest_port}", "comment", comment]


    def mk_failopen_rule(self, proto, dest_port, comment):
        if proto:
            return ["allow", f"{dest_port}/{proto}", "comment", comment]
        else:
            return ["allow", f"{dest_port}", "comment", comment]


    def mk_delete_rule(self, src_ip, proto, dest_port):
        if src_ip.lower() == 'anywhere':
            if proto:
                return ["delete", "allow", f"{dest_port}/{proto}"]
            else:
                return ["delete", "allow", f"{dest_port}"]
        else:
            if proto:
                return ["delete", "allow", "from", src_ip, "proto", proto,
                        "to", "any", "port", f"{dest_port}"]
            else:
                return ["delete", "allow", "from", src_ip,
                        "to", "any", "port", f"{dest_port}"]


    def parse_ufw_rules(self, rule_output):
        allow_rules = []
        failopen_rules = []
        for line in rule_output.splitlines():
            m = self.re_rule.match(line.decode())
            if not m:
                continue
            l = m.group(1).split('/')
            proto = None if len(l) < 2 else l[1].lower()
            rule = { 'port': int(l[0]),
                     'proto': proto,
                     'action': m.group(2).lower(),
                     'from': m.group(3) }
            comment_text = m.group(4)

            c = self.re_cmt_allow.match(comment_text)
            if c and c.group(1) == 'allow':
                # allow rule
                rule['id'] = c.group(2)  # id
                rule['expire'] = c.group(3)  # expire
                allow_rules.append(rule)
            else:
                c = self.re_cmt_fopen.match(comment_text)
                if c and c.group(1) == 'fail':
                    rule['expire'] = c.group(2)
                    failopen_rules.append(rule)
                else:
                    print("Error parsing comment: '{}'".format(comment_text))

        return allow_rules, failopen_rules


    def get_active_rules(self):
        rc, out, err = self.run_ufw(['status'])
        if rc != 0:
            print("Error running command '{cmd}'. Stderr: {err}".format(cmd=self.base_cmd, err=err))
            return None
    
        allow_rules, failopen_rules = self.parse_ufw_rules(out)
        if allow_rules == [] and failopen_rules == []:
            self.rules_present = False
        else:
            self.rules_present = True

        return allow_rules, failopen_rules


    def remove_expired_rules(self):
        current_epoch = int(time.time())
        # record the nearest expiration that is not yet expired
        # we'll use this to know when we need to check here again,
        # but we'll check at least every 6 seconds
        next_expiration = current_epoch + 6

        # If we know there are no rules present, then just return
        if not self.rules_present:
            return next_expiration
        
        knock_rules, fail_rules = self.get_active_rules()

        self.logger.debug("Check for expired firewall rules")

        def delete_rule(expire, frm, proto, port):
            nonlocal next_expiration
            expire = int(expire)
            if current_epoch > expire:
                del_rule = self.mk_delete_rule(frm, proto, port)
                rc, out, err = self.run_ufw(del_rule)
                if rc:
                    self.logger.error(f"Error deleting knock rule: '{err}'")
                else:
                    self.logger.info(f"Deleted firewall rule: {del_rule} " + \
                                     f"expiration: {expire}, current time: {current_epoch}")
            else:
                if next_expiration == 0 or next_expiration > expire:
                    next_expiration = expire

        for rule in knock_rules:
            delete_rule(int(rule['expire']), rule['from'], rule['proto'], rule['port'])

        for rule in fail_rules:
            delete_rule(int(rule['expire']), rule['from'], rule['proto'], rule['port'])

        return next_expiration


    def add_new_rule(self, src_ip, proto, dest_port, id, duration):
        epoch = int(time.time())
        self.logger.debug(f"Adding new fw rule at time {epoch}. Src:{src_ip}, " + \
                         f"Port:{dest_port}, Id:{id}, Duration: {duration}")
        rule = self.mk_allow_rule(src_ip, proto, dest_port, 
                                  self.mk_allow_comment(id, int(duration) + epoch))
        rc, out, err = self.run_ufw(rule)
        self.rules_present = True
        if rc != 0:
            self.logger.error(f"Error adding firewall rule:'{rule}'. Error msg:'{err}'")


    def add_failopen_rules(self):
        if self.cfg.listener.failopen:
            self.logger.info("Adding failopen rules for ports: {}".format(self.cfg.listener.failopen_ports))
            for item in self.cfg.listener.failopen_ports:
                if not item:
                    continue
                elif len(item) == 1:
                    item.append(None)

                c = self.mk_failopen_comment()
                rule = self.mk_failopen_rule(item[1], int(item[0]), c)
                rc, out, err = self.run_ufw(rule)
                self.rules_present = True
                if rc != 0:
                    self.logger.error(f"Error adding failopen rule: {err}")
        else:
            self.logger.info("Failopen is disabled. Skipping.")


    def run_ufw(self, args):

        p = subprocess.run(self.base_cmd + args, capture_output=True)
        return (p.returncode, p.stdout, p.stderr)