from os import popen, path
from subprocess import check_output
from .custom_logger import log_me, logging
from time import sleep

class convert2pcap(object):
    def __init__(self, sid):
        self.sessionid = f'_{sid}'

    def cv2pc(self, sniffer_input):
        self.conv_folder = 'pcap_conversion_files/'
        self.input_file = f'{self.conv_folder}sniffer_input_file{self.sessionid}'
        self.output_file = f'{self.conv_folder}sniffer_output_file{self.sessionid}.pcap'
        if sniffer_input:
            perl_version = str(check_output(['perl', '-v', '|', 'grep', 'version']))
            if 'version' in perl_version:
                with open(self.input_file, 'w') as sif:
                    for line in sniffer_input:
                        sif.write(line)
                self.pexec = popen(f'perl fgt2eth.pl -in {self.input_file} -out {self.output_file}')
                while not path.isfile(self.output_file):
                    sleep(2)
                if path.isfile(self.output_file):
                    log_me(logging.INFO, f'Converted {sif} to new.pcap!')
                    return self.output_file, self.input_file
                else:
                    log_me(logging.ERROR, f'Missing File from system. Conversion did not work')
            else:
                log_me(logging.ERROR, f'Missing Perl from system. Please install Perl before running.')
        else:
            log_me(logging.ERROR, f'File sniffer_input is missing')

