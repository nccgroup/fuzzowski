from .irestarter import IRestarter
import subprocess
import shlex


class CmdRestarter(IRestarter):

    def __init__(self, cmd, *args, **kwargs):
        self.cmd = cmd

    @staticmethod
    def name() -> str:
        return 'run'

    @staticmethod
    def help():
        return "'<executable> [<argument> ...]' (Pass command and arguments within quotes, as only one argument)"

    def restart(self, *args, **kwargs):
        subprocess.call(shlex.split(self.cmd))
        return f"Executing command: {self.cmd}"

