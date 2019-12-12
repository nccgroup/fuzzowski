import abc


class IRestarter(object, metaclass=abc.ABCMeta):
    """Describes a Restarter Module interface.
    """

    @abc.abstractmethod
    def __init__(self, *args, **kwargs):
        pass

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
    def restart(self, *args, **kwargs) -> str or None:
        """Restart the target with magic"""
        pass
