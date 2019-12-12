from .ifuzzer import IFuzzer
from fuzzowski import Session
from fuzzowski.mutants.spike import *


class TFTP(IFuzzer):
    """TFTP Fuzzer

    Trivial FTP Fuzzer, incomplete
    """

    name = 'tftp'

    @staticmethod
    def get_requests() -> List[callable]:
        """Get possible requests"""
        return [TFTP.read, TFTP.write]

    @staticmethod
    def define_nodes(*args, **kwargs) -> None:

        # Read
        s_initialize('read')
        s_static(b'\x00\x01', name="opcode")
        s_string(b'File.bin', name="source_file")
        s_delim(b'\x00')
        s_string(b'netascii', name="transfer_mode")
        s_delim(b'\x00')

        # --------------------------------------------------------------- #

        # Write
        s_initialize('write')
        s_static(b'\x00\x02', name="opcode")
        s_string(b'File.txt', name="source_file")
        s_delim(b'\x00')
        s_string(b'netascii', name="transfer_mode")
        s_delim(b'\x00')

        # --------------------------------------------------------------- #

    @staticmethod
    def read(session: Session) -> None:
        session.connect(s_get('read'))

    @staticmethod
    def write(session: Session) -> None:
        session.connect(s_get('write'))
