import abc
from typing import List


class IFuzzer(object):
    """Describes a fuzzer interface.
    """

    name = 'Implement'
    requests = []

    @staticmethod
    @abc.abstractmethod
    def get_requests() -> List[callable]:
        """Get possible requests"""
        raise NotImplementedError("Subclasses should implement this!")

    @staticmethod
    @abc.abstractmethod
    def define_nodes(*args, **kwargs) -> None:
        """Get possible requests"""
        raise NotImplementedError("Subclasses should implement this!")
