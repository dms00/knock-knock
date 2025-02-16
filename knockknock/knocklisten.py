#!/usr/bin/env python3

import argparse
import os
import sys
import time

import config
import firewall
import knocktrack
import log
import tcpdump



def create_pidfile(cfg, logger):
    try:
        pf = open(cfg.listener.pidfile, "xt")
    except FileExistsError as e:
        logger.critical("Pid file already exists. Exiting.")
        sys.exit(1)
    
    pf.write(str(os.getpid()))
    pf.close()


def main_loop(cfg, logger):

    fw = firewall.Firewall(cfg, logger)

    td = tcpdump.Tcpdump(cfg, logger)

    ktrack = []
    # Create one knocktrack object for each client
    for clicfg in cfg.clients:
        logger.debug("clicfg.name = '{}'".format(clicfg.name))
        kt = knocktrack.KnockTrack(cfg, clicfg, logger, fw)
        ktrack.append(kt)

    next_fw_rule_check = 0
    knock_housekeeping_due = int(time.time()) + 5

    try:
        while True:
            # line = next(tail)
            line = td.tail()
            current_epoch = int(time.time())
            if line:
                # entry = ul.match(line)
                entry = td.match(line)
                if entry:
                    logger.debug('Log line entry: {}'.format(entry))
                    for k in ktrack:
                        k.process_knock(entry)
                    # do housekeeping at least every 5 seconds
                    knock_housekeeping_due = current_epoch + 5

            # Housekeeping
            if next_fw_rule_check <= current_epoch:
                next_fw_rule_check = fw.remove_expired_rules()
            # knock track housekeeping is run on every process_knock, but do this
            # in case there are no knocks to process
            if current_epoch > knock_housekeeping_due:
                for k in ktrack:
                    k.housekeeping()
    except Exception as e:
        logger.critical(e)
        raise e
    finally:
        logger.info("Attempting to add failopen rules if enabled.")
        fw.add_failopen_rules()


def main(argv):

    tmp_logger = log.Log("info", False)

    argp = argparse.ArgumentParser(prog='knocklisten',
                                   description='Service that listens for port knocking.')
    argp.add_argument('--config-file',
                      required=False,
                      default="/etc/knockknock/knock.toml",
                      help="Path to global configuration file.")

    args = argp.parse_args()

    # load config
    cfg = config.Config(args.config_file, tmp_logger)
    # initialize logger
    logger = log.Log(cfg.logging.log_level, cfg.logging.syslog)
    tmp_logger = None

    create_pidfile(cfg, logger)
    try:
        main_loop(cfg, logger)
    except:
        # bare except because we want to try to remove the PID file
        # no matter what error we've encountered
        raise
    finally:
        os.remove(cfg.listener.pidfile)


if __name__ == '__main__':
    main(sys.argv)
