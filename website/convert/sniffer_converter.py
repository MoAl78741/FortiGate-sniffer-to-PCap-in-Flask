from os import path, makedirs, getcwd, remove
from subprocess import check_output, run
from .custom_logger import log_me, logging
from time import sleep
import re

class Convert2Pcap(object):
    def __init__(self, tid: int, cid: int, tuid: int, fname: str, file_to_convert: str):
        self.taskid = f'_{tid}'
        self.currentuserid = f'_{cid}'
        self.tasuserid = f'_{tuid}'
        self.file_to_convert = file_to_convert
        self.base_path = f'{getcwd()}/website/convert/'
        self.conv_folder = f'{self.base_path}pcap_conversion_files/'
        self.filename = f'{self.conv_folder}{fname}'
        self.filename_nopath = fname
        self.logs_folder = f'{self.base_path}_logs/'
        self.num_of_packets_captured = 0

    def create_directories(self) -> bool:
        '''Creates and checks for directories'''
        directories = [self.logs_folder, self.conv_folder]
        [makedirs(x, exist_ok=True) for x in directories]
        for dir in directories:
            if not path.exists(dir):
                raise Exception(f'Missing directory: {dir}: Cannot continue.')
            return True
  
    def writeout_file(self, file_name: str, file_content: str) -> bool:
        '''Writes out file to disk for processing'''
        with open(file_name, 'w') as output_file:
            for line in file_content.splitlines():
                output_file.write(f'{line}\n')
        if not path.exists(file_name):
            raise Exception(f'Missing file: {file_name}: Cannot continue.')
        return True

    def packets_captured(self, original_file: str) -> bool:
        '''Returns number of packets originally received by filter'''
        regex_string = r"\d+ packets received by filter"
        regex_compiled = re.compile(regex_string)
        with open(original_file, 'r') as ofile:
            ofile_contents = ofile.read()
        regex_results = re.findall(regex_compiled, ofile_contents)
        if not regex_results:
            return None
        num_packets_captured = regex_results[0].split().pop(0)
        if num_packets_captured:
            log_me(logging.INFO, f"Packets originally captured in {self.filename} is {num_packets_captured}")
            self.num_of_packets_captured = num_packets_captured
        return True

    def remove_file(self, file):
        '''Removes files from disk'''
        remove(file)
        assert not path.isfile(file)

    @staticmethod
    def is_file_created(file: str) -> bool:
        '''Loops for 60sec checking for file on disk'''
        timer = 30
        while not path.isfile(file):
                    sleep(2)
                    timer -= 1
                    if timer == 0:
                        return False
        if not path.isfile(file):
            return False
        return True    

    def check_perl_exists(self) -> bool:
        '''Checks if perl is installed on system'''
        perl_version = str(check_output(['perl', '-v', '|', 'grep', 'version']),)
        if 'version' not in perl_version:
            log_me(logging.ERROR, f'Missing Perl from system. Please install Perl before running.')
            raise Exception("Perl is required but not installed. ")
        return True
    
    def run_text_to_hex_conversion(self, input_filename: str, output_file: str) -> bool:
        '''Runs original file against fgt2eth[x].pl to convert to a hex text file'''
        pexec = run(["perl", "website/convert/fgt2eth2.pl", "-in", input_filename], capture_output=True)
        hex_resultsc = pexec.stdout.decode()
        assert self.writeout_file(output_file, hex_resultsc)
        hex_file_exists = self.is_file_created(output_file)
        if not hex_file_exists:
            raise Exception('Unable to create Hex File')
        if not path.isfile(output_file):
            log_me(logging.ERROR, f'Missing hex file from system. Conversion did not work')
        log_me(logging.INFO, f'Converted {output_file} to hex capture')
        return True

    def run_hex_to_pcap_conversion(self, hex_file: str, pcap_file: str) -> bool:
        '''Runs hex text file against text2pcap for pcap conversion'''
        if not hex_file:
            raise Exception('Hex pcap text file does not exist')
        if not path.isfile(hex_file):
            raise Exception('Error when running text2pcap')
        pexec = run(f'text2pcap -q -t "%d/%m/%Y %H:%M:%S." {hex_file} {pcap_file}', shell=True, check=True, timeout=3)
        if pexec.returncode != 0:
            raise Exception("Unable to convert hex filet to PCAP file.")
        return True     
 
    def text_to_hex_capture(self) -> str:
        '''Does the work for text to hex'''
        created_directories = self.create_directories()
        original_file = self.writeout_file(self.filename, self.file_to_convert)
        assert self.packets_captured(self.filename)
        if not created_directories or not original_file:
            raise Exception(f'Something went wrong with file or directories. Cannot continue.')
        input_filename = self.filename
        output_file = f'{self.conv_folder}task{self.taskid}_user{self.currentuserid}_{self.filename_nopath}.converted'
        if not path.exists(input_filename):
            log_me(logging.ERROR, f'File sniffer_input is missing')
        assert self.check_perl_exists()
        assert self.run_text_to_hex_conversion(input_filename, output_file)
        self.remove_file(input_filename)
        return output_file

    def convert_from_hex_to_pcap(self) -> str:
        '''Does the work for hex to pcap'''
        hex_file = self.text_to_hex_capture()
        pcap_file = f'{self.conv_folder}task{self.taskid}_user{self.currentuserid}_{self.filename_nopath}.pcap'
        assert self.run_hex_to_pcap_conversion(hex_file, pcap_file)
        pcap_file_exists = self.is_file_created(pcap_file)
        if not pcap_file_exists:
            raise Exception('Unable to create PCAP File')
        if not path.isfile(pcap_file):
            return None
        self.remove_file(hex_file)
        return pcap_file, self.num_of_packets_captured

    @classmethod
    def run_conversion(cls, tid, cid, tuid, fname, file_to_convert) -> str:
        '''Used to execute the class'''
        return cls(tid, cid, tuid, fname, file_to_convert).convert_from_hex_to_pcap()