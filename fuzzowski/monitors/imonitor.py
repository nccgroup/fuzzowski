import abc
from fuzzowski import Session
from copy import deepcopy
from ..connections import ITargetConnection
from ..testcase import TestCase


class IMonitor(metaclass=abc.ABCMeta):
    """
    Describes a Monitor Module interface.

    The run() function will be called after each test to check if the target is still running
    """

    def __init__(self, session: Session, *args, **kwargs):
        self.session = session
        self.logger = self.session.logger # We save the logger to call it easier

    def get_connection_copy(self) -> ITargetConnection:
        """
        Helper. Copy the connection to the target and returns it
        Returns:
            The connection to the target
        """
        conn = deepcopy(self.session.target._target_connection)
        return conn

    def run(self, test_case: TestCase):
        """
        This is the function that is called by the Session after each Test. It launches the test() method, which is the
         main method that needs to be overridden by any Monitor implemented.
        """
        self.logger.open_test_step(f"Calling Monitor {self.name()}")
        try:
            result = self.test()
            if not result:
                self.logger.log_error(f"Monitor {self.name()} Failed!")
                if test_case is not None:
                    self.session.add_suspect(test_case)
                else:
                    self.logger.log_error('No test_case in session to add as suspect!')
            else:
                self.logger.log_info(f"Monitor {self.name()} succeeded")
        except Exception as e:
            # Ignore exceptions
            self.session.logger.log_error(f"The monitor threw an exception: {str(e)}")

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
    def test(self) -> bool:
        """ This is the function that has the main functionality of the monitor. When this function returns False, the
        actual Test Case is added as a Suspect

        Returns: True if everything is OK. False if the monitor failed"""
        pass
