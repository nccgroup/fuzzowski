from typing import Dict, Union

from .block import Block
from .checksum import Checksum
from .request import Request
from .size import Size
from .repeat import Repeat
from .variable import Variable

# __all__ = [Block, Request, Size, Checksum, Repeat, Variable]

REQUESTS: Dict[str, Request] = {}       # Variable where all requests created with s_initialize will be
CURRENT: Union[Request, None] = None    # Current Request
