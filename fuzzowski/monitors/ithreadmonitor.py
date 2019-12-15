from abc import ABCMeta
from threading import Thread
from .imonitor import IMonitor
from fuzzowski import Session


class IThreadMonitor(Thread, IMonitor, metaclass=ABCMeta):
    """
    Describes a Threaded Monitor Module interface.

    Inherits also from Thread, the run() function will be called when the thread starts (only runs once).
    """

    def __init__(self, session: Session, *args, **kwargs):
        Thread.__init__(self)
        IMonitor.__init__(self, session, *args, **kwargs)
        self._stop = False
