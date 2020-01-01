#!/usr/bin/python3
"""
Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Mario Rivas, mario.rivas@nccgroup.com

http://www.github.com/nccgroup/fuzzowski

Forked From BooFuzz and Sulley
https://github.com/jtpereyda/boofuzz

Licensed under GNU General Public License v2.0 - See LICENSE.txt
"""

import argparse
import importlib
import os
import re
import hashlib
import sys

from fuzzowski import *
from fuzzowski.fuzzers import IFuzzer
from fuzzowski.mutants import REQUESTS, String
from fuzzowski.restarters import IRestarter
from fuzzowski.monitors import IMonitor, IThreadMonitor

from fuzzowski.session import Session

logo = """                                       
       ■      ■       
       ■■■■■■■■       
      ■■■■■■■■■■      
     ■■  ■■■■  ■■     
     ■■  ■■■■  ■■     
    ■■■■      ■■■■    
   ■ ■■■■■■■■■■■■ ■   
   ■  ■■■■■■■■■■  ■   Fuzzowski Network Fuzzer
   ■    ■     ■   ■           🄯  Fuzzers, inc.
       ■■     ■■               by Mario Rivas"""


class Fuzzowski(object):
    position_pattern = re.compile('({{.*?}})')
    base_value_pattern = re.compile('^{{(.*?)}}$')

    def __init__(self):
        self.session = None

        self._init_argparser()
        self.args = self._parse_args()

        # Create session
        if self.args.protocol == 'telnet':  # TODO: Set this automatically from fuzzers without modifying main program!
            self.target = Target(connection=TelnetConnection(self.args.host,
                                                             port=self.args.port,
                                                             timeout=self.args.recv_timeout,
                                                             username=self.args.username,
                                                             password=self.args.password
                                                             )
                                 )
        else:
            self.target = Target(connection=SocketConnection(self.args.host,
                                                             self.args.port,
                                                             proto=self.args.protocol,
                                                             bind=self.args.bind,
                                                             send_timeout=self.args.send_timeout,
                                                             recv_timeout=self.args.recv_timeout
                                                             )
                             )

        self.session = Session(session_filename=self.session_filename,
                               sleep_time=self.args.sleep_time,
                               # restart_interval=0,
                               crash_threshold_request=self.args.crash_threshold_request,
                               crash_threshold_element=self.args.crash_threshold_element,
                               restart_sleep_time=self.args.restart_sleep_time,
                               # fuzz_loggers=None,
                               receive_data_after_each_request=self.args.receive_data_after_each_request,
                               check_data_received_each_request=self.args.check_data_received_each_request,
                               receive_data_after_fuzz=self.args.receive_data_after_fuzz,
                               ignore_connection_issues_after_fuzz=self.args.ignore_connection_issues_after_fuzz,
                               target=self.target,
                               restarter=self.restart_module,
                               monitors=self.monitors,
                               new_connection_between_requests=self.args.new_connection_between_requests,
                               transmit_full_path=self.args.transmit_full_path
                               )

        # Connect nodes of graph
        if self.args.fuzz_protocol == 'raw' and self.fuzz_requests is not None:
            requests = self._generate_requests_from_strings(self.fuzz_requests)
            for i in range(0, len(requests)):
                if i == 0:
                    self.session.connect(requests[i])
                if len(requests) > 1:
                    self.session.connect(requests[i], requests[i + 1])

        elif self.fuzz_methods is not None:
            for fuzz_method in self.fuzz_methods:
                fuzz_method(self.session)
        else:
            raise Exception("Impossibru!")

        if self.args.filename is not None:
            self._set_file_for_strings(REQUESTS.values(), self.args.filename)
        elif self.args.callback is not None:
            self._set_callback_for_strings(REQUESTS.values(), self.args.callback)

    # --------------------------------------------------------------- #

    def _init_argparser(self):
        """
        Initializes the argparser inside self.parser
        """

        # This parser0 is a little parser to be able to append fuzzer modules with include before
        parser0 = argparse.ArgumentParser(usage=argparse.SUPPRESS, add_help=False)
        parser0.add_argument('-i', dest="include", nargs='+', help="Include modules from path[s]")
        args0, others = parser0.parse_known_args()
        if args0.include is not None:
            for path in args0.include:
                self.import_modules_from_path(path)

        self.parser = argparse.ArgumentParser(
            description= logo ,
            formatter_class=argparse.RawTextHelpFormatter)

        self.parser.add_argument("host", help="Destination Host")
        self.parser.add_argument("port", type=int, help="Destination Port")
        conn_grp = self.parser.add_argument_group('Connection Options')
        conn_grp.add_argument("-p", "--protocol", dest="protocol", help="Protocol (Default tcp)", default='tcp',
                              choices=['tcp', 'udp', 'ssl'])
        conn_grp.add_argument("-b", "--bind", dest="bind", type=int, help="Bind to port")
        conn_grp.add_argument("-st", "--send_timeout", dest="send_timeout", type=float, default=5.0,
                              help="Set send() timeout (Default 5s)")
        conn_grp.add_argument("-rt", "--recv_timeout", dest="recv_timeout", type=float, default=5.0,
                              help="Set recv() timeout (Default 5s)")
        conn_grp.add_argument("--sleep-time", dest="sleep_time", type=float, default=0.0,
                              help="Sleep time between each test (Default 0)")
        conn_grp.add_argument('-nc', '--new-conns', dest='new_connection_between_requests',
                              help="Open a new connection after each packet of the same test",
                              action='store_true')
        conn_grp.add_argument('-tn', '--transmit_full_path', dest='transmit_full_path',
                              help="Transmit the next node in the graph of the fuzzed node",
                              action='store_true')
        recv_grp = self.parser.add_argument_group('RECV() Options')
        recv_grp.add_argument('-nr', '--no-recv', dest='receive_data_after_each_request',
                              help="Do not recv() in the socket after each send",
                              action='store_false')
        recv_grp.add_argument('-nrf', '--no-recv-fuzz', dest='receive_data_after_fuzz',
                              help="Do not recv() in the socket after sending a fuzzed request",
                              action='store_false')
        recv_grp.add_argument('-cr', '--check-recv', dest='check_data_received_each_request',
                              help="Check that data has been received in recv()",
                              action='store_true')

        crash_grp = self.parser.add_argument_group('Crashes Options')
        crash_grp.add_argument("--threshold-request", dest="crash_threshold_request", type=int, default=9999,
                               help="Set the number of allowed crashes in a Request before skipping it (Default 9999)")
        crash_grp.add_argument("--threshold-element", dest="crash_threshold_element", type=int, default=3,
                               help="Set the number of allowed crashes in a Primitive before skipping it (Default 3)")
        crash_grp.add_argument('--error-fuzz-issues', dest='ignore_connection_issues_after_fuzz',
                               help="Log as error when there is any connection issue in the fuzzed node",
                               action='store_true')

        fuzz_grp = self.parser.add_argument_group('Fuzz Options')
        fuzz_grp_opts = fuzz_grp.add_mutually_exclusive_group()
        fuzz_grp_opts.add_argument('-c', '--callback', dest='callback',
                              default=None,
                              help="Set a callback address to fuzz with callback generator instead of normal mutations")
        fuzz_grp_opts.add_argument('--file', dest='filename', help='Use contents of a file for fuzz mutations')

        fuzzers = [fuzzer_class.name for fuzzer_class in IFuzzer.__subclasses__()] + ['raw']
        protocols_help = 'Requests of the protocol to fuzz, default All\n'
        for fuzzer_protocol in IFuzzer.__subclasses__():
            methods = ', '.join([req.__name__ for req in fuzzer_protocol.get_requests()])
            protocols_help += '  {}: [{}]\n'.format(fuzzer_protocol.name, methods)
        protocols_help += '  {}: [{}]'.format('raw', repr("'\x01string\n' '\x02request2\x00' ...").strip('"'))
        fuzzers_grp = self.parser.add_argument_group('Fuzzers')
        fuzzers_grp.add_argument('-i', dest="include", nargs='+', help="Include modules from path[s]",
                                 metavar="PATH")
        fuzzers_grp.add_argument("-f", "--fuzz", dest="fuzz_protocol", help='Available Protocols', required=True,
                                 choices=fuzzers)
        fuzzers_grp.add_argument("-r", "--requests", dest="fuzz_requests", nargs='+', default=[],
                                 help=protocols_help, required=False)

        restarters_grp = self.parser.add_argument_group('Restart options')
        restarters_help = 'Restarter Modules:\n'
        for restarter in IRestarter.__subclasses__():
            restarters_help += '  {}: {}\n'.format(restarter.name(), restarter.help())
        restarters_grp.add_argument('--restart', nargs='+', default=[], metavar=('module_name', 'args'),
                                    help=restarters_help)
        restarters_grp.add_argument("--restart-sleep", dest="restart_sleep_time", type=int, default=5,
                                    help='Set sleep seconds after a crash before continue (Default 5)')

        monitor_classes = [monitor_class for monitor_class in IMonitor.__subclasses__() if monitor_class != IThreadMonitor]
        monitor_names = [monitor.name() for monitor in monitor_classes]
        monitors_grp = self.parser.add_argument_group('Monitor options')
        monitors_help = 'Monitor Modules:\n'
        for monitor in monitor_classes:
            monitors_help += '  {}: {}\n'.format(monitor.name(), monitor.help())
        monitors_grp.add_argument('--monitors', '-m', nargs='+', default=[],
                                  help=monitors_help, choices=monitor_names)

        other_grp = self.parser.add_argument_group('Other Options')
        other_grp.add_argument("--path", dest="path", default='/',
                               help='Set path when fuzzing HTTP based protocols (Default /)')
        other_grp.add_argument("--document_url", dest="document_url", default='http://127.0.0.1/',
                               help='Set Document URL for print_uri')

    # --------------------------------------------------------------- #

    def _parse_args(self) -> argparse.Namespace:
        """
        Parse arguments with argparse

        Returns:
            (argparse.Namespace) Argparse arguments
        """
        args = self.parser.parse_args()
        if args.filename:
            fuzz_opts = 'file'
        elif args.callback:
            fuzz_opts = 'callback'
        else:
            fuzz_opts = 'default'

        if args.fuzz_protocol == 'raw':  # Raw chosen, lets define packets
            if not args.fuzz_requests:
                print('When choosing raw you must define the packets with the -r option!')
                exit(1)
            self.fuzz_requests = args.fuzz_requests
            self.session_filename = '{}_{}_{}_{}_{}_{}.session'.format(
                args.fuzz_protocol,
                args.host,
                args.port,
                args.protocol,
                fuzz_opts,
                hashlib.md5(", ".join(args.fuzz_requests).encode('utf-8')).hexdigest(),
            )
        else:  # Already defined protocol
            fuzz_protocol = [icl for icl in IFuzzer.__subclasses__() if icl.name == args.fuzz_protocol][0]
            fuzz_protocol.define_nodes(**args.__dict__)
            for method_name in args.fuzz_requests:
                if method_name not in [req.__name__ for req in fuzz_protocol.get_requests()]:
                    print('Protocol {} only allows the following methods') \
                        .format(args.fuzzer_protocol.__name__,
                                ', '.join([req.__name__ for req in args.fuzzer_protocol.get_requests()]))
                    exit(1)
            self.fuzz_requests = args.fuzz_requests
            if len(self.fuzz_requests) > 0:
                self.fuzz_methods = [getattr(fuzz_protocol, method_name) for method_name in args.fuzz_requests]
            else:  # All methods
                self.fuzz_methods = [method for method in fuzz_protocol.get_requests()]
            if len(args.fuzz_requests) == 1:
                reqs = args.fuzz_requests[0]
            else:
                reqs = hashlib.md5(", ".join(args.fuzz_requests).encode('utf-8')).hexdigest()
            self.session_filename = '{}_{}_{}_{}_{}_{}.session'.format(
                args.fuzz_protocol,
                args.host,
                args.port,
                args.protocol,
                fuzz_opts,
                reqs
            )

        self.restart_module = None
        if len(args.restart) > 0:
            try:
                restart_module = [mod for mod in IRestarter.__subclasses__() if mod.name() == args.restart[0]][0]
                restart_args = args.restart[1:]
                self.restart_module = restart_module(*restart_args)
            except IndexError:
                print(f"The restarter module {args.restart[0]} does not exist!")
                exit(1)


        self.monitors = []
        if len(args.monitors) > 0:
            self.monitors = [mon for mon in IMonitor.__subclasses__() if mon != IThreadMonitor and mon.name() in args.monitors]

        return args

    # --------------------------------------------------------------- #

    def _set_file_for_strings(self, block_list: "list of IFuzzable", filename: str) -> None:
        """
        Walk the nodes setting a filename for the strings to replace the fuzzing library

        Args:
            block_list (list of IFuzzable): List of blocks (usualldefine_nodesy Request)
            filename (str): file name to add

        Returns:
            None
        """
        for block in block_list:
            if hasattr(block, 'stack'):
                self._set_file_for_strings(block.stack, filename)
            else:
                if isinstance(block, String):
                    block.set_filename(filename)

    def _set_callback_for_strings(self, block_list: "list of IFuzzable", callback: str) -> None:
        """
        Walk the nodes setting a callback for the strings to replace the fuzzing library

        Args:
            block_list (list of IFuzzable): List of blocks (usually Request)
            callback (str): callback IP or domain name (e.g. something from burp collaborator)

        Returns:
            None
        """
        for block in block_list:
            if hasattr(block, 'stack'):
                self._set_callback_for_strings(block.stack)
            else:
                if isinstance(block, String):
                    block.set_callback_commands(callback)

    # --------------------------------------------------------------- #

    @staticmethod
    def _generate_requests_from_strings(fuzz_requests: "list of str") -> "list of Request":
        """
        Generate and initialize Requests from strings with format when "raw" protocol selected.
        See examples in argparse

        Args:
            fuzz_requests: list of strings, one packet for string

        Returns:
            list of Request: list of initialized Requests
        """
        str_i = 1
        req_i = 1
        requests = []
        for fuzz_request in fuzz_requests:
            request_name = 'request{}'.format(req_i)
            uni_request = fuzz_request.encode().decode('unicode_escape')
            s_initialize(request_name)
            for block_split in Fuzzowski.position_pattern.split(uni_request):
                if Fuzzowski.base_value_pattern.match(block_split):
                    # Base Value inside, add String
                    base_value = Fuzzowski.base_value_pattern.match(block_split).groups()[0]
                    #s_string(base_value, name='{}_{}'.format(base_value, str_i))
                    s_string(base_value)
                    str_i += 1
                else:
                    # Other thing, add Static if len > 0
                    if len(block_split) > 0:
                        s_static(block_split)
                        # TODO: Identify delimiters, bytes, ...
            requests.append(s_get(request_name))
            req_i += 1

        return requests

    # --------------------------------------------------------------- #

    def run(self):
        """Start the session fuzzer!"""
        self.session.start()

    # --------------------------------------------------------------- #

    @staticmethod
    def import_modules_from_path(path):
        if os.path.isdir(path):
            modules = [f.split('.')[0] for f in os.listdir(path) if f.endswith(".py")]
            sys.path.insert(0, path)
            for module in modules:
                importlib.import_module(module)
        elif os.path.isfile(path) and path.endswith('.py'):
            sys.path.insert(0, os.path.dirname(path))
            module = os.path.split(path)[-1].split('.py')[0]
            importlib.import_module(module)
        else:
            print(f'The path {path} is not valid')
            exit(1)

# --------------------------------------------------------------- #


def main():
    netfuzzer = Fuzzowski()
    # print(REQUESTS)
    # print(blocks.REQUESTS)
    # print(blocks.CURRENT)
    print(logo)
    netfuzzer.run()


if __name__ == '__main__':
    main()
