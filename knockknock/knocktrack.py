import time
import totpmgr


# Track ongoing knock sequences
class KnockTrack:
    def __init__(self, cfg, clicfg, logger, firewall):
        self.logger = logger
        self.firewall = firewall
        self.knock_expiration = cfg.listener.knock_expiration
        self.totp_mgr = totpmgr.TotpMgr(clicfg, self.knock_expiration, logger)
        self.clicfg = clicfg
        self.knock_tracking = {}


    def housekeeping(self):
        self.totp_mgr.rotate_totp()
        self.remove_expired_sessions()


    def remove_expired_sessions(self):
        # reduce current time by 1 second to add a bit of slop.
        # there can be a fraction of a second delay between a
        # knock event in the log and the time it gets processed.
        curr_epoch = int(time.time())-1

        expired_sips = []
        for source_ip, ksession_list in self.knock_tracking.items():
            expired = []
            for k in ksession_list:
                # We don't want to modify the list we're iterating over,
                # so record refs to list items and remove them later.
                if curr_epoch > k['expiration']:
                    expired.append(k)

            for k in expired:
                self.logger.debug(f"Removing expired session: {k}")
                ksession_list.remove(k)
            
            # if list is empty record source_ip to delete later
            if not ksession_list:
                expired_sips.append(source_ip)

        for sip in expired_sips:
            self.logger.debug(f"Removing empty source IP from knock data: {source_ip}")
            del self.knock_tracking[sip]


    def test_nth_knock(self, ksession, knock_epoch, dport, msg_len):
        match, done = False, False

        kd = ksession['kd']
        knock_idx = ksession['knock_cnt']

        if kd['ports'][knock_idx] == dport and kd['lens'][knock_idx] == msg_len and \
           knock_epoch <= ksession['expiration']:

            self.logger.debug(f"Knock {knock_idx+1} received for client " + \
                              f"'{self.clicfg.name}', port={dport} len={msg_len}")
            
            # Successful match, so increment cnt
            ksession['knock_cnt'] += 1
            match = True

            # Test if knock sequence is complete
            if ksession['knock_cnt'] >= len(kd['ports']):
                done = True

        return match, done


    def test_first_knock(self, epoch, dport, msg_len):
        kd_list = [self.totp_mgr.knock_data]
        if epoch <= self.totp_mgr.old_knock_data['expiration']:
            kd_list.append(self.totp_mgr.old_knock_data)

        for kd in kd_list:
            self.logger.debug(f"Testing first knock: curr={kd}. dport={dport}, len={msg_len}")
            if (kd['ports'][0] == dport) and (kd['lens'][0] == msg_len) and (epoch >= kd['start_epoch']):
                self.logger.debug(f"First knock received for client '{self.clicfg.name}', port={dport} len={msg_len}")
                return kd
        
        return None


    def start_knock_tracking(self, kd, epoch, source_ip):
        new_session = dict(kd=kd, expiration=epoch+self.knock_expiration, knock_cnt=1)

        if source_ip in self.knock_tracking:
            self.knock_tracking[source_ip].append(new_session)
        else:
            self.knock_tracking[source_ip] = [new_session]


    def open_door(self, source_ip):
        id = self.clicfg.name
        duration = self.clicfg.open_duration
        self.logger.info(f"Opening ports for client '{id}'")

        for p in self.clicfg.ports:
            port_str = f"{p[0]}" + (f"/{p[1]}" if p[1] else "")
            self.logger.info(f"Opening port {port_str} for {source_ip}")
            self.firewall.add_new_rule(source_ip, p[1], p[0], id, duration)


    # knock_session: { kd: <ptr to Totpmgr.knock_data at start of this session>,
    #                  expiration: epoch,
    #                  knock_cnt: <number of knocks that have matched> }
    #
    # knock_tracking: { source_ip: [ knock_session, knock_session, ... ],
    #                   source_ip: [ ..., ], }

    def process_knock(self, knock):
        # knock: {ts: <epoch_timestamp>, saddr: <source_ip>, dport: <dest_port>, len: <data length>}

        self.housekeeping()
        source_ip = knock['saddr']        
        done, found = False, False
        # Check if knock belongs to any in-progress sessions from this IP
        if source_ip in self.knock_tracking:
            for i, ksession in enumerate(self.knock_tracking[source_ip]):
                found, done = self.test_nth_knock(ksession, 
                                                  knock['ts'], 
                                                  knock['dport'], 
                                                  knock['len'])
                if done or found:
                    break

            # if we completed a knock sequence, open door and remove from list
            if done:
                self.open_door(source_ip)
                self.knock_tracking[source_ip].pop(i)

            if not self.knock_tracking[source_ip]:
                self.logger.debug(f"Deleting {source_ip} from knock_tracking")
                del self.knock_tracking[source_ip]

        # if knock doesn't belong to existing sessions test for new session
        if not found:
            # Test if a new knock session is starting
            kd = self.test_first_knock(knock['ts'], knock['dport'], knock['len'])
            if kd:
                self.start_knock_tracking(kd, knock['ts'], source_ip)
