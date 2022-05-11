import logging
from datetime import date
from os import getcwd

class log_me(object):

    def __init__(self, loglevel, msg):
        self.logname = f'{getcwd()}/website/convert/_logs/logfile' + str(date.today()) + f'.log'

        logging.basicConfig(format='%(levelname)s | %(asctime)s | %(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p',
                            filename=self.logname,
                            filemode='a',
                            level=logging.INFO)
        logging.log(loglevel, msg)
        print(f'{msg}')


