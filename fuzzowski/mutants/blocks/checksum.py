import hashlib
import struct
import zlib
from functools import wraps
from typing import Union

from fuzzowski.exception import FuzzowskiRuntimeError
from ..mutant import Mutant
from ...constants import LITTLE_ENDIAN
from ..blocks.request import Request
from ...helpers import helpers


def _may_recurse(f):
    @wraps(f)
    def safe_recurse(self, *args, **kwargs):
        self._recursion_flag = True
        result = f(self, *args, **kwargs)
        self._recursion_flag = False
        return result

    return safe_recurse


class Checksum(Mutant):

    checksum_lengths = {
        "crc32": 4,
        "adler32": 4,
        "md5": 16,
        "sha1": 20,
        "ipv4": 2,
        "udp": 2
    }

    def __init__(self, block_name: str, request: Request, algorithm: Union[str, callable] = "crc32",
                 output_format: str = "binary", length: int = 0, endian: chr = LITTLE_ENDIAN, fuzzable: bool = True,
                 name: str = None, ipv4_src_block_name: str = None, ipv4_dst_block_name: str = None):
        """
        Checksum bound to the block with the specified name.

        The algorithm may be chosen by name with the algorithm parameter, or a custom function may be specified with
        the algorithm parameter.

        The length field is only necessary for custom algorithms.

        Recursive checksums are supported; the checksum field itself will render as all zeros for the sake of checksum
        or length calculations.

        Args:
            block_name:             Name of target block for checksum calculations.
            request:                Request this block belongs to
            algorithm:              (Optional, def=crc32) Checksum algorithm to use.
                                    (crc32, adler32, md5, sha1, ipv4, udp)
            output_format           (def=binary). Output format of the checksum (Current options: binary, hex)
            length:                 (Optional, def=0) Length of checksum, auto-calculated by default.
            endian:                 (Optional, def=LITTLE_ENDIAN) Endianess of the bit field
                                    (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
            fuzzable:               (Optional, def=True) Enable/disable fuzzing of this block
            name:                   (Optional, def=None) Specifying a name gives you direct access to the block
            ipv4_src_block_name:    Required for 'udp' algorithm. Name of block yielding IPv4 source address
            ipv4_dst_block_name:    Required for 'udp' algorithm. Name of block yielding IPv4 destination address
        """
        self._block_name = block_name
        self._request = request
        self._algorithm = algorithm
        self._length = length
        self._endian = endian
        self._output_format = output_format
        self._name = name
        self._ipv4_src_block_name = ipv4_src_block_name
        self._ipv4_dst_block_name = ipv4_dst_block_name

        self._fuzzable = fuzzable

        if not self._length and self._algorithm in self.checksum_lengths.keys():
            self._length = self.checksum_lengths[self._algorithm]

        # Edge cases and a couple arbitrary strings (all 1s, all Es)
        self._mutations = [b'\x00' * self._length,
                              b'\x11' * self._length,
                              b'\xEE' * self._length,
                              b'\xFF' * self._length,
                              b'\xFF' * (self._length - 1) + b'\xFE',
                              b'\x00' * (self._length - 1) + b'\x01']

        if self._algorithm == 'udp':
            if not self._ipv4_src_block_name:
                raise FuzzowskiRuntimeError("'udp' checksum algorithm requires ipv4_src_block_name")
            if not self._ipv4_dst_block_name:
                raise FuzzowskiRuntimeError("'udp' checksum algorithm requires ipv4_dst_block_name")

        self._rendered = self._get_dummy_value()

        # Set the recursion flag before calling a method that may cause a recursive loop.
        self._recursion_flag = False

        super().__init__(self._rendered, name, fuzzable, mutations=self._mutations)

    def render(self, replace_node=None, replace_value=None, original=False):
        """
        Calculate the checksum of the specified block using the specified algorithm.
        """
        if replace_node is not None and replace_value is not None and replace_node == self.name:
            self._rendered = replace_value
        if self._should_render_fuzz_value():
            self._rendered = self._value
        elif self._recursion_flag:
            self._rendered = self._get_dummy_value()
        else:
            self._rendered = self._checksum(data=self._render_block(self._block_name),
                                            ipv4_src=self._render_block(self._ipv4_src_block_name),
                                            ipv4_dst=self._render_block(self._ipv4_dst_block_name))

        self._rendered = self._format(self._rendered)
        return self._rendered

    def _format(self, value):
        if self._output_format == 'binary':
            return value
        elif self._output_format == 'hex':
            return value.hex().encode('utf-8')
        else:
            raise FuzzowskiRuntimeError(f'Checksum output format not supported: {self._output_format}')

    def _should_render_fuzz_value(self):
        return self._fuzzable and (self._mutant_index != 0) and not self._fuzz_complete

    def _get_dummy_value(self):
        if self._length:
            return self._length * b'\x00'
        return self.checksum_lengths[self._algorithm] * b'\x00'

    @_may_recurse
    def _render_block(self, block_name):
        return self._request.names[block_name].render() if block_name is not None else None

    def _checksum(self, data: bytes, ipv4_src, ipv4_dst):
        """
        Calculate and return the checksum (in raw bytes) of data.

        :param data Data on which to calculate checksum.
        :type data bytes

        :rtype:  str
        :return: Checksum.
        """
        if type(self._algorithm) is str:
            if self._algorithm == "crc32":
                check = struct.pack(self._endian + "L", (zlib.crc32(data) & 0xFFFFFFFF))

            elif self._algorithm == "adler32":
                check = struct.pack(self._endian + "L", (zlib.adler32(data) & 0xFFFFFFFF))

            elif self._algorithm == "ipv4":
                check = struct.pack(self._endian + "H", helpers.ipv4_checksum(data))

            elif self._algorithm == "udp":
                return struct.pack(self._endian + "H",
                                   helpers.udp_checksum(msg=data,
                                                        src_addr=ipv4_src,
                                                        dst_addr=ipv4_dst,
                                                        )
                                   )

            elif self._algorithm == "md5":
                digest = hashlib.md5(data).digest()

                # TODO: is this right?
                if self._endian == ">":
                    (a, b, c, d) = struct.unpack("<LLLL", digest)
                    digest = struct.pack(">LLLL", a, b, c, d)

                check = digest

            elif self._algorithm == "sha1":
                digest = hashlib.sha1(data).digest()

                # TODO: is this right?
                if self._endian == ">":
                    (a, b, c, d, e) = struct.unpack("<LLLLL", digest)
                    digest = struct.pack(">LLLLL", a, b, c, d, e)

                check = digest

            else:
                raise FuzzowskiRuntimeError("INVALID CHECKSUM ALGORITHM SPECIFIED: %s" % self._algorithm)
        else:
            check = self._algorithm(data)

        if self._length:
            return check[:self._length]
        else:
            return check

    @property
    def original_value(self):
        if self._recursion_flag:
            return self._get_dummy_value()
        else:
            return self._checksum(data=self._original_value_of_block(self._block_name),
                                  ipv4_src=self._original_value_of_block(self._ipv4_src_block_name),
                                  ipv4_dst=self._original_value_of_block(self._ipv4_dst_block_name))

    @_may_recurse
    def _original_value_of_block(self, block_name):
        return self._request.names[block_name].original_value if block_name is not None else None

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, self._name)

    def __len__(self):
        return len(self.render())
        # return self._length

    def __nonzero__(self):
        """
        Make sure instances evaluate to True even if __len__ is zero.

        :return: True
        """
        return True
