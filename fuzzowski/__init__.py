"""
Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Mario Rivas, mario.rivas@nccgroup.com

http://www.github.com/nccgroup/fuzzowski

Forked From BooFuzz and Sulley
https://github.com/jtpereyda/boofuzz

Licensed under GNU General Public License v2.0 - See LICENSE.txt
"""

from fuzzowski.helpers import deprecated
from . import exception
from .constants import BIG_ENDIAN, LITTLE_ENDIAN
from .loggers.fuzz_logger import FuzzLogger
from .connections import ITargetConnection
from .exception import FuzzowskiRuntimeError, SizerNotUtilizedError, MustImplementException
from .connections import SocketConnection, TelnetConnection
from .connections.target import Target
from .loggers import IFuzzLogger
from .mutants import Request
from .mutants.spike import *
from .session import Session
from .responses import *
__version__ = '0.8.2'
