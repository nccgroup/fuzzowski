from prompt_toolkit.styles import Style
from prompt_toolkit import PromptSession, HTML, print_formatted_text
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
import sys

from .commands import CommandHandler, CommandCompleter, COMMANDS
from .helpers import get_tokens


class CommandPrompt(object):
    def __init__(self) -> None:
        self.commands = self.get_commands()
        self.cmd_handler = CommandHandler(self.commands)
        self.completer = CommandCompleter(self.commands)
        self.style = self.get_style()
        self._break = False
        self.prompt_session = PromptSession(completer=self.completer, style=self.style,
                                            bottom_toolbar=self.bottom_toolbar,
                                            auto_suggest=AutoSuggestFromHistory())
        super(CommandPrompt, self).__init__()

    # --------------------------------------------------------------- #

    def get_commands(self):
        return COMMANDS

    # --------------------------------------------------------------- #

    def get_prompt(self):
        return HTML('<b>> </b>')

    # --------------------------------------------------------------- #

    def get_style(self):
        Style.from_dict({
            'completion-menu.completion': 'bg:#008888 #ffffff',
            'completion-menu.completion.current': 'bg:#00aaaa #000000',
            'scrollbar.background': 'bg:#88aaaa',
            'scrollbar.button': 'bg:#222222',
            'token.literal.string.single': '#98ff75'
        })

    # --------------------------------------------------------------- #

    def intro_message(self):
        print_formatted_text(HTML('<b>Starting prompt...</b>'))
    # --------------------------------------------------------------- #

    def exit_message(self):
        print_formatted_text(HTML('<b>Exiting prompt...</b>'))

    # --------------------------------------------------------------- #

    def handle_exit(self, tokens: list) -> None:
        if len(tokens) > 0:
            if tokens[0] in ('exit', 'quit', 'q'):
                # TODO: exit gracefully
                sys.exit(0)

    # --------------------------------------------------------------- #

    def handle_break(self, tokens: list) -> bool:
        if tokens[0] in ('c', 'continue'):
            return True
        else:
            return False
    # --------------------------------------------------------------- #

    def handle_command(self, tokens: list) -> None:
        if len(tokens) > 0:
            self.cmd_handler.handle_command(tokens)

    # --------------------------------------------------------------- #

    def bottom_toolbar(self):
        return None

    # --------------------------------------------------------------- #

    def start_prompt(self) -> None:
        self.intro_message()
        while True:
            try:
                cmd = self.prompt_session.prompt(
                    self.get_prompt,
                )

                tokens = get_tokens(cmd)

                if not self.handle_break(tokens):
                    self.handle_exit(tokens)
                    self.handle_command(tokens)

            except KeyboardInterrupt:
                continue
            except EOFError:
                # self.handle_exit(['exit'])
                break
        self.exit_message()
