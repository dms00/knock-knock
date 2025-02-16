import logging
import logging.handlers


class Log:
    level_names = { logging.DEBUG: "DEBUG",
                    logging.INFO: "INFO",
                    logging.WARNING: "WARNING",
                    logging.ERROR: "ERROR",
                    logging.CRITICAL: "CRITICAL" }
    custom_levels = { "DEBUG": logging.DEBUG,
                      "INFO": logging.INFO,
                      "WARNING": logging.WARNING,
                      "ERROR": logging.ERROR,
                      "CRITICAL": logging.CRITICAL }
    
    def __init__(self, log_level, to_syslog=True):
        self.log_level = self.custom_levels.get(log_level.upper(), logging.WARNING)
        #self.prefix = "[KNOCK {level}] "
        self.logger = logging.getLogger("knock-knock")
        self.logger.setLevel(self.log_level)

        for handler in list(self.logger.handlers):
            self.logger.removeHandler(handler)
        
        if to_syslog:
            handler = logging.handlers.SysLogHandler(address = '/dev/log')
        else:
            handler = logging.StreamHandler()
        formatter = logging.Formatter('%(name)s: %(levelname)s %(message)s')

        handler.setFormatter(formatter)
        self.logger.addHandler(handler)


    def set_level(self, log_level):
        self.log_level = self.custom_levels.get(log_level.upper(), logging.WARNING)
        self.logger.setLevel(self.log_level)


    @classmethod
    def level_name(cls, log_level):
        return cls.level_names.get(log_level, None)


    def critical(self, msg, *args, **kwargs):
        self.logger.critical(msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        self.logger.error(msg, *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        self.logger.warning(msg, *args, **kwargs)

    def info(self, msg, *args, **kwargs):
        self.logger.info(msg, *args, **kwargs)

    def debug(self, msg, *args, **kwargs):
        self.logger.debug(msg, *args, **kwargs)
