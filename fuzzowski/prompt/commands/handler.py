import traceback
from prompt_toolkit import HTML, print_formatted_text
from prompt_toolkit.formatted_text import FormattedText


class CommandHandler(object):
    def __init__(self, commands: dict) -> None:
        self.commands = commands
        super().__init__()

    # ---------------------------------------------------------------#

    def execute_command(self, cmd: list) -> None:
        if cmd[0] in self.commands:
            entry = self.commands[cmd[0]]
            if 'exec' in entry and entry['exec']:
                entry['exec'](cmd[1:])
        else:
            print_formatted_text(
                FormattedText([('class:red', f'{cmd[0]}: Command not found')]))

    # ---------------------------------------------------------------#

    def handle_command(self, cmd: list) -> None:
        if cmd[0] == '':
            return
        try:
            self.execute_command(cmd)
        except Exception as e:
            print_formatted_text(
                FormattedText([('class:red', f'Execution of {cmd[0]} failed. {traceback.format_exc()}')]))

