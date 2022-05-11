from os import path, makedirs, getcwd, remove
from subprocess import check_output, call, run
from .custom_logger import log_me, logging
from time import sleep

class Convert2Pcap(object):
    def __init__(self, tid: int, cid: int, tuid: int, fname, file_to_convert):
        self.taskid = f'_{tid}'
        self.currentuserid = f'_{cid}'
        self.tasuserid = f'_{tuid}'
        self.file_to_convert = file_to_convert
        self.base_path = f'{getcwd()}/website/convert/'
        self.conv_folder = f'{self.base_path}pcap_conversion_files/'
        self.filename = f'{self.conv_folder}{fname}'
        self.filename_nopath = fname
        self.logs_folder = f'{self.base_path}_logs/'

    def create_directories(self):
        directories = [self.logs_folder, self.conv_folder]
        [makedirs(x, exist_ok=True) for x in directories]
        for dir in directories:
            if not path.exists(dir):
                raise Exception(f'Missing directory: {dir}: Cannot continue.')
            else:
                return True

    def writeout_original_file(self):
        with open(self.filename, 'w') as original_file:
            for line in self.file_to_convert.splitlines():
                original_file.write(f'{line}\n')
        if not path.exists(self.filename):
            raise Exception(f'Missing file: {self.filename}: Cannot continue.')
        else:
            return True

    def writeout_hex_file(self, output_filename, file_content):
        with open(output_filename, 'w') as output_file:
            for line in file_content.splitlines():
                output_file.write(f'{line}\n')
        if not path.exists(output_filename):
            raise Exception(f'Missing file: {output_filename}: Cannot continue.')
        else:
            return True

    @staticmethod
    def is_file_created(file):
        while not path.isfile(file):
                    sleep(2)
        if path.isfile(file):
            return True
        else:
            return False

 
    def text_to_hex_capture(self):
        created_directories = self.create_directories()
        original_file = self.writeout_original_file()
        if not created_directories or not original_file:
            raise Exception(f'Something went wrong with file or directories. Cannot continue.')
        input_filename = self.filename
        output_file = f'{self.conv_folder}task{self.taskid}_user{self.currentuserid}_{self.filename_nopath}.converted'
        if path.exists(input_filename):
            perl_version = str(check_output(['perl', '-v', '|', 'grep', 'version']),)
            if 'version' in perl_version:

                pexec = run(["perl", "website/convert/fgt2eth2.pl", "-in", input_filename], capture_output=True)
                hex_resultsc = pexec.stdout.decode() 
                self.writeout_hex_file(output_file, hex_resultsc)
      
                hex_file_exists = self.is_file_created(output_file)
                if not hex_file_exists:
                    raise Exception('Unable to create Hex File')

                if path.isfile(output_file):
                    log_me(logging.INFO, f'Converted {output_file} to hex capture')
                    remove(input_filename)
                    # return output_file, input_filename
                    return output_file
                else:
                    log_me(logging.ERROR, f'Missing File from system. Conversion did not work')
            else:
                log_me(logging.ERROR, f'Missing Perl from system. Please install Perl before running.')
        else:
            log_me(logging.ERROR, f'File sniffer_input is missing')

    def convert_from_hex_to_pcap(self):
        hex_file = self.text_to_hex_capture()
        pcap_file = f'{self.conv_folder}task{self.taskid}_user{self.currentuserid}_{self.filename_nopath}.pcap'
        if hex_file:
            if path.isfile(hex_file):
                pexec = run(f'text2pcap -q -t "%d/%m/%Y %H:%M:%S." {hex_file} {pcap_file}', shell=True)
                if 'returncode=0' in str(pexec):
                    pcap_file_exists = self.is_file_created(pcap_file)
                    if not pcap_file_exists:
                        raise Exception('Unable to create PCAP File')

                    if path.isfile(pcap_file):
                        remove(hex_file)
                        return pcap_file
                    else:
                        print('\nfile does not exist\n')
                else:
                    raise Exception('Error when running text2pcap')
            else:
                print('\n file does not exist2\n')

    @classmethod
    def run_conversion(cls, tid, cid, tuid, fname, file_to_convert):
        return cls(tid, cid, tuid, fname, file_to_convert).convert_from_hex_to_pcap()

