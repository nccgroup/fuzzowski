import abc
from ..sessions import Session


class IMonitor(metaclass=abc.ABCMeta):
    """
    Describes a Monitor Module interface.

    The run() function will be called after each test to check if the target is still running
    """

    def __init__(self, session: Session, *args, **kwargs):
        self.session = session

    @staticmethod
    @abc.abstractmethod
    def name() -> str:
        """Get name"""
        pass

    @staticmethod
    @abc.abstractmethod
    def help():
        """ Get help string"""
        pass

    @abc.abstractmethod
    def run(self):
        pass

