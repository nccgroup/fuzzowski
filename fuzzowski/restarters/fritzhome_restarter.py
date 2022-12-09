from .irestarter import IRestarter
from fuzzowski import FuzzLogger
from fuzzowski.loggers import FuzzLoggerText
from pyfritzhome import Fritzhome
from time import sleep

# Use with --restarter fritzhome "<host>" "<user>" "<password>" "<ain>" --restart-delay <delay>
class FritzhomeRestarter(IRestarter):

    def __init__(self, host, user, password, ain, *args, **kwargs):
        
        self.logger = FuzzLogger([FuzzLoggerText()])
        self.logger.log_info(f"Initializing FritzhomeRestarter with host: {host}, user: {user}, password: {password}, ain: {ain}")
        self.fritz = Fritzhome(host, user, password)
        self.fritz.login()
        self.device = self.fritz.get_device_by_ain(ain)
        self.logger.log_info(f"Device: {self.device}")

    @staticmethod
    def name() -> str:
        return 'fritzhome'

    @staticmethod
    def help():
        return 'Restart the target by toggling a Fritz!DECT smart plug'

    def restart(self, *args, **kwargs) -> str or None:
        self.logger.log_info("Restarting target")
        switch_state = self.device.set_switch_state_toggle()
        self.logger.log_info(f"Switch state: {switch_state}")
        sleep(1)
        switch_state = self.device.set_switch_state_toggle()
        self.logger.log_info(f"Switch state: {switch_state}")
        return "Restarted target"
