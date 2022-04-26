import logging
from datetime import date

class log_me(object):

    def __init__(self, loglevel, msg):
        self.logname = f'log_files/logfile' + str(date.today()) + f'.log'

        logging.basicConfig(format='%(levelname)s | %(asctime)s | %(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p',
                            filename=self.logname,
                            filemode='a',
                            level=logging.INFO)
        logging.log(loglevel, msg)
        print(f'{msg}')


