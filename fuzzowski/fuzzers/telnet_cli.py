from typing import List
from .ifuzzer import IFuzzer
from .. import *
from ..sessions import Session


class TelnetCLI(IFuzzer):
    """
    Example module for fuzzing a CLI over Telnet (using the TelnetConnection Module)
    """

    name = 'telnet_cli'

    @staticmethod
    def get_requests() -> List[callable]:
        return [TelnetCLI.commands]

    @staticmethod
    def define_nodes(*args, **kwargs) -> None:

        s_initialize('example_command')
        s_string(b'ping', fuzzable=False)
        s_delim(b' ',     fuzzable=True, name='delim_space')
        s_string(b'1.2.3.4',    fuzzable=True, name='ip')
        s_delim(b'\r\n',     fuzzable=False)

    # --------------------------------------------------------------- #

    @staticmethod
    def commands(session: Session) -> None:
        session.connect(s_get('example_command'))


