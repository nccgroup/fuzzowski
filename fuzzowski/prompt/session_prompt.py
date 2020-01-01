import os
import sys
import signal
from typing import TYPE_CHECKING
from prompt_toolkit import HTML, print_formatted_text
from prompt_toolkit.styles import Style, merge_styles

from fuzzowski import constants
from fuzzowski import exception

from .prompt import CommandPrompt

if TYPE_CHECKING:
    from fuzzowski.session import Session


class SessionPrompt(CommandPrompt):

    def __init__(self, session: 'Session'):
        super().__init__()
        self.session: 'Session' = session
        signal.signal(signal.SIGINT, self._signal_handler)

    # ================================================================#
    # CommandPrompt Overridden Functions                              #
    # ================================================================#

    def get_commands(self):
        """ Contains the full list of commands"""
        commands = super().get_commands()
        commands.update({
            'env': {
                'desc': 'Show Session Information',
                'exec': self._cmd_env
            },
            'goto': {
                'desc': 'Go to test case by index',
                'exec': self._cmd_goto
            },
            'next': {
                'desc': 'Run next test case',
                'exec': self._cmd_run_next
            },
            'print': {
                'desc': 'Print a test case by index',
                'exec': self._cmd_print_test_case
            },
            'poc': {
                'desc': 'Print the python poc code of test case by index',
                'exec': self._cmd_print_poc_test_case
            },
            'suspects': {
                'desc': 'print information about the tests suspected of crashing something',
                'exec': self._cmd_suspects
            },
            'suspects-del': {
                'desc': 'delete suspect',
                'exec': self._cmd_delsuspect
            },
            'disabled-elements': {
                'desc': 'List the disabled elements',
                'exec': self._cmd_list_disabled_elements
            },
            'disable': {
                'desc': 'Disable a fuzzing element',
                'exec': self._cmd_disable
            },
            'enable': {
                'desc': 'Enable a disabled element',
                'exec': self._cmd_enable
            },
            'fuzz': {
                'desc': 'Fuzz a test case by index',
                'exec': self._cmd_fuzz_single_case
            },
            'restart': {
                'desc': 'Launch the restarter module to restart the target',
                'exec': self._cmd_restart
            },
            'skip': {
                'desc': 'Skip the actual mutant',
                'exec': self._cmd_skip
            },
            'test': {
                'desc': 'Send the actual case without fuzzing',
                'exec': self._cmd_test_single_case
            },
            'crash': {
                'desc': 'Mark test case as crash. Saving the poc in the results folder',
                'exec': self._cmd_addcrash
            },

        })
        return commands

    # --------------------------------------------------------------- #

    def get_prompt(self):
        host = self.session.target.target_connection.host
        port = str(self.session.target.target_connection.port)

        return HTML('[<testn>{} of {}</testn>] '
                    '<b>➜</b> <host>{}</host>:<port>{}</port> $ '
                    .format(self.session.mutant_index, self.session.total_mutations, host, port))

    # --------------------------------------------------------------- #

    def bottom_toolbar(self):
        if self.session.test_case is not None:
            toolbar_message = HTML(f'Test Case [<bttestn>{self.session.mutant_index}</bttestn>] '
                                   f'of [<bttestn>{self.session.total_mutations}</bttestn>]'
                                   f': Fuzzing Path <bttestn>{self.session.test_case.path_name}</bttestn> '
                                   f' Mutant <bttestn>{self.session.test_case.short_name}</bttestn>')
        else:
            toolbar_message = HTML(f'Test Case [<bttestn>{self.session.mutant_index}</bttestn>] '
                                   f'of [<bttestn>{self.session.total_mutations}</bttestn>]')

        return toolbar_message

    # --------------------------------------------------------------- #

    def handle_break(self, tokens: list) -> bool:
        if tokens[0] in ('c', 'continue'):
            self.session.is_paused = False
            self.session.run_all()
            return True
        else:
            return False

    # --------------------------------------------------------------- #

    def handle_exit(self, tokens: list) -> None:
        if len(tokens) > 0:
            if tokens[0] in ('exit', 'quit', 'q'):
                self.session.export_file()
                sys.exit(0)

    # --------------------------------------------------------------- #

    def _signal_handler(self, _signal, frame):
        self.session.is_paused = True
        try:
            print_formatted_text(HTML(' <testn>SIGINT received. Pausing fuzzing after this test case...</testn>'),
                                 style=self.get_style())
            #self.logger.log_info("SIGINT received. Pausing fuzzing after this test case...")
        except RuntimeError:
            # prints are not safe in signal handlers.
            # This happens if the signal is catch while printing
            pass

    # --------------------------------------------------------------- #

    def _print_color(self, color, message):
        print_formatted_text(HTML(f'<{color}>{message}</{color}>'),
                             style=self.get_style())

    # --------------------------------------------------------------- #

    def _print_error(self, message):
        self._print_color('red', message)

    # ================================================================#
    # Command handlers                                                #
    # ================================================================#

    def _cmd_disable(self, tokens):
        try:

            self.session.disable_by_path_name(tokens[0])
        except IndexError:
            self._print_error('disable usage: disable REQUEST_NAME.MUTANT_NAME')
            return
        except exception.FuzzowskiRuntimeError as e:
            self._print_error(e)

    # --------------------------------------------------------------- #

    def _cmd_enable(self, tokens):
        try:

            self.session.disable_by_path_name(tokens[0], disable=False)
        except IndexError:
            self._print_error('Usage: enable REQUEST_NAME.MUTANT_NAME')
            return
        except exception.FuzzowskiRuntimeError as e:
            self._print_error(e)

    def _cmd_env(self, _):
        self._print_color('gold', 'Session Options:')
        for k, v in self.session.opts.__dict__.items():
            print(f'  {str(k)} = {str(v)}')

        self._print_color('gold', '\nSuspects:')
        self._cmd_suspects([])

        self._print_color('gold', '\nDisabled Elements:')
        self._cmd_list_disabled_elements([])

        self._print_color('gold', '\nPaths:')
        actual_request = None
        if self.session.test_case is not None:
            actual_request = self.session.test_case.request
        for path in self.session.graph.path_iterator():
            print(f"[{' -> '.join([edge.dst.name for edge in path])}]")
            for edge in path:
                mutants_list = edge.dst.list_fuzzable_mutants()
                print(f'  {edge.dst.__class__.__name__}: {edge.dst.name}\t {"[DISABLED]" if edge.dst.disabled else ""}')
                for mutant in mutants_list:
                    print(f'    {mutant.__class__.__name__}: {edge.dst.name}.{mutant.name}\t (Def Val: {mutant.original_value}) {"[DISABLED]" if mutant.disabled else ""}')
            print('')

    def _cmd_list_disabled_elements(self, tokens):
        for path_name, elem in self.session.disabled_elements.items():
            print(f'{path_name} ({type(elem).__name__})')

    # --------------------------------------------------------------- #

    def _cmd_goto(self, tokens):
        """
        Move to test case number

        :param tokens: list of args, should have only an integer
        :return: None
        """
        try:
            try:
                mutant_index = int(tokens[0])
                self.session.goto(mutant_index)
            except IndexError:
                self._print_error(f'<red>goto usage: goto [TEST_ID|PATH]. Example:\n'
                                  f'\tgoto 10\n'
                                  f'\tgoto request1.mutant1</red>')
                return
            except ValueError:
                self.session.goto(tokens[0])
        except exception.FuzzowskiRuntimeError as e:
            self._print_error(str(e))

    # --------------------------------------------------------------- #

    def _cmd_run_next(self, tokens):
        """
        Run the actual test case and move to next one

        :param tokens: Not used
        :return: None
        """
        if self.session.mutant_index == 0 and self.session.test_case is None:
            # In the mutant index 0, the first next will just go to 1 without doing nothing
            self.session.run_next(force=True)

        self.session.run_next(force=True)

    # --------------------------------------------------------------- #

    def _cmd_print_test_case(self, tokens):
        try:
            test_case_index = int(tokens[0])
        except IndexError:  # No index specified, print actual case
            if self.session.test_case is not None:
                self.session.test_case.print_requests()
            return
        except ValueError:
            self._print_error('print usage: print [TEST_ID]')
            return
        session_state = self.session.save_session_state()
        self.session.goto(test_case_index)
        if self.session.test_case is not None:
            self.session.test_case.print_requests()
        self.session.load_session_state(session_state)

    def _cmd_print_poc_test_case(self, tokens):
        try:
            test_case_index = int(tokens[0])
        except IndexError: # No index specified, print actual case
            if self.session.test_case is not None:
                self.session.test_case.print_poc()
            return
        except ValueError:
            self._print_error('poc usage: poc [TEST_ID]')
            return
        session_state = self.session.save_session_state()
        self.session.goto(test_case_index)
        if self.session.test_case is not None:
            self.session.test_case.print_poc()
        self.session.load_session_state(session_state)

    # --------------------------------------------------------------- #

    def _cmd_skip(self, _):
        self.session.skip()
    # --------------------------------------------------------------- #

    def _cmd_suspects(self, tokens):
        try:
            test_case_index = int(tokens[0])
            suspect = self.session.suspects[test_case_index]
            print(suspect.info())
        except IndexError:  # No index specified, Show all suspects
            for suspect_id, suspect in self.session.suspects.items():
                if suspect is not None:
                    print(suspect.info())
                else:
                    print(f'Test Case {suspect_id}')
            return
        except ValueError:
            self._print_error('suspects usage: suspects [TEST_ID]')
            return
        except KeyError:
            self._print_error(f'Suspect with id {tokens[0]} not found')

    def _cmd_delsuspect(self, tokens):
        try:
            test_case_index = int(tokens[0])
            suspect = self.session.suspects.pop(test_case_index)
            print(f'Removing {suspect} from suspects')
        except IndexError:  # No index specified, Show all suspects
            self._print_error('delsuspect usage: delsuspect TEST_ID')
            return
        except ValueError:
            self._print_error('delsuspect usage: delsuspect TEST_ID')
            return
        except KeyError:
            self._print_error(f'Suspect with id {tokens[0]} not found')

    # --------------------------------------------------------------- #

    def _cmd_fuzz_single_case(self, tokens):
        """
        Save actual state, fuzz single case (number) and restore state

        :param tokens: list of args, should have only an integer
        :return: None
        """
        try:
            test_case_index = int(tokens[0])
            session_state = self.session.save_session_state()
            self.session.goto(test_case_index)
            self.session.run()
            self.session.load_session_state(session_state)
        except IndexError:  # No index specified, Fuzz current case
            self.session.run()
        except ValueError:
            self._print_error('Usage: fuzz [TEST_ID]')
            return

    # --------------------------------------------------------------- #

    def _cmd_restart(self, _):
        """
        Launch the restarter module of the session, if a restarter module was set
        """
        self.session.restart_target()

    # --------------------------------------------------------------- #

    def _cmd_test_single_case(self, tokens):
        """
        Save actual state, fuzz single case (number) and restore state

        :param tokens: list of args, should have only an integer
        :return: None
        """
        try:
            test_case_index = int(tokens[0])
            self.session.test(test_case_index)
        except IndexError:  # No index specified, Fuzz current case
            self.session.test()
        except ValueError:
            self._print_error('Usage: test [TEST_ID]')
            return

    # --------------------------------------------------------------- #

    def _cmd_addcrash(self, tokens):
        try:
            test_case_index = int(tokens[0])
        except IndexError:  # No index specified, Show crashes?
            self._print_error('Usage: crash [TEST_ID]')
            return
        except ValueError:
            self._print_error('Usage: crash [TEST_ID]')
            return
        session_state = self.session.save_session_state()
        self.session.goto(test_case_index)
        if self.session.test_case is not None:
            poc_code = self.session.test_case.get_poc()
            # TODO: host,port,proto may be not available, call public functions
            host = self.session.target._target_connection.host
            port = self.session.target._target_connection.port
            proto = self.session.target._target_connection.proto
            name = self.session.test_case.short_name
            poc_filename = os.path.join(constants.RESULTS_DIR,
                                        f'poc_{host}_{port}_{proto}_{test_case_index}_{name}.py')
            print_formatted_text(HTML(f'Writing PoC to file: <testn>{poc_filename}</testn>'),
                                 style=self.get_style())
            with open(poc_filename, 'w') as f:
                f.write(poc_code)
        self.session.load_session_state(session_state)

    # --------------------------------------------------------------- #

    def get_style(self):
        return merge_styles([super().get_style(), Style.from_dict(constants.STYLE)])

    # --------------------------------------------------------------- #

    def intro_message(self):
        print_formatted_text(HTML('Fuzzing paused! Welcome to the <b>Fuzzowski Shell</b>'))

    # --------------------------------------------------------------- #

    def exit_message(self):
        print_formatted_text(HTML('<b>Exiting prompt...</b>'))

    # --------------------------------------------------------------- #
