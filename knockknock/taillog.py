
import os
import time



class TailLog():
    def __init__(self, cfg, logger, logfile_name):
        self.logger = logger
        self.cfg = cfg
        self.logfile_name = logfile_name
        self.generator = self.tail()
        self.total_line_count = 0
        self.current_line_count = 0

    def truncate(self):
        self.current_line_count = 0
        self.f.seek(0, os.SEEK_SET)

    def next(self):
        return next(self.generator)
    
    def _open_file(self):
        self.current_line_count = 0
        f = open(self.logfile_name, "r")
        f.seek(0, 2)  # seek to end of file
        self.curr_inode = os.fstat(f.fileno()).st_ino
        return f

    def _test_inode(self):
        return os.stat(self.logfile_name).st_ino == self.curr_inode

    def tail(self):
        self.f = self._open_file()

        while True:
            l = self.f.readline()
            if l:
                self.total_line_count += 1
                self.current_line_count += 1
                yield l
            else:
                # Check if file has been rotated and we need to open
                # the new file.
                if not self._test_inode():
                    self.f.close()
                    self.f = self._open_file()
                else:
                    yield None
