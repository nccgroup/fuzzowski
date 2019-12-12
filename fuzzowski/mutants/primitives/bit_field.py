import struct
from typing import Union, List, Tuple

from ..mutant import Mutant
from ...constants import LITTLE_ENDIAN


def binary_string_to_int(binary: Union[bytes, str]) -> int:
    """
    Convert a binary string to a decimal number.
    Args:
        binary: Binary string

    Returns:
        int: Converted bit string
    """
    return int(binary, 2)


def int_to_binary_string(number: int, bit_width: int) -> str:
    """

    Args:
        number: Number to convert
        bit_width: Width of bit string

    Returns:
        str: Bit string
    """
    return "".join(map(lambda x: str((number >> x) & 1), range(bit_width - 1, -1, -1)))


def bytes_to_string(b: bytes) -> str:
    """
    Convert bytes to string

    Args:
        b: Bytes

    Returns:
        str: String
    """
    rendered = ''
    for i in b:
        rendered += chr(i)
    return rendered


def string_to_bytes(s: str) -> bytes:
    """
    Convert string to bytes

    Args:
        s: String

    Returns:
        bytes: Bytes
    """
    b_list = []
    for c in s:
        b_list.append(ord(c))
    return bytes(b_list)


class BitField(Mutant):
    def __init__(self, value: int, width: int, max_num: int = None,
                 endian: chr = LITTLE_ENDIAN, output_format: str = "binary", signed: bool = False,
                 full_range: bool = False, fuzzable: bool = True, name: str = None,
                 mutations: Union[List[int], Tuple[int]] = ()):
        """
        The bit field primitive represents a number of variable length and is used to define all other integer types.

        Args:
            value:          Default integer value
            width:          Width of bit fields
            max_num:        (Optional, def=None) Maximum number to iterate up to
            endian:         (Optional, def=LITTLE_ENDIAN) Endianess of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
            output_format:  (Optional, def=binary) Output format, "binary" or "ascii"
            signed:         (Optional, def=False) Make size signed vs. unsigned (applicable only with format="ascii")
            full_range:     (Optional, def=False) If enabled the field mutates through *all* possible values.
            fuzzable:       (Optional, def=True) Enable/disable fuzzing of this primitive
            name:           (Optional, def=None) Specifying a name gives you direct access to a primitive
            mutations:      (Optional, def=()) Specify the list of mutations to override the default ones
        """
        # super().__init__(value, name, fuzzable)

        assert isinstance(value, (int,)), "value must be an integer!"
        assert isinstance(width, (int,)), "width must be an integer!"
        assert output_format in ("binary", "ascii"), "output_format must be 'binary' or 'ascii'!"

        self._value = value
        # I have deleted the possibility of setting a bit field with bytes
        self._original_value = self._value
        self.width = width
        self.max_num = max_num
        self.endian = endian
        self.format = output_format
        self.signed = signed
        self.full_range = full_range
        self._fuzzable = fuzzable
        self._name = name
        self.cyclic_index = 0         # when cycling through non-mutating values

        self._mutations = list(mutations)
        self._mutation_gen = self.mutation_generator()
        self._disabled = False

        if not self.max_num:
            self.max_num = binary_string_to_int("1" + "0" * width)
        assert isinstance(self.max_num, (int, )), "max_num must be an integer!"

        if self.full_range:
            # add all possible values.
            for i in range(0, self.max_num):
                self._mutations.append(i)
        else:
            if len(mutations) == 0:
                # try only "smart" values.
                self.add_integer_boundaries(0)
                self.add_integer_boundaries(self.max_num // 2)
                self.add_integer_boundaries(self.max_num // 3)
                self.add_integer_boundaries(self.max_num // 4)
                self.add_integer_boundaries(self.max_num // 8)
                self.add_integer_boundaries(self.max_num // 16)
                self.add_integer_boundaries(self.max_num // 32)
                self.add_integer_boundaries(self.max_num)

            # TODO: Add injectable arbitrary bit fields

    @property
    def original_value(self) -> bytes:
        return self._render(self._original_value)

    def add_integer_boundaries(self, integer):
        """
        Add the supplied integer and border cases to the integer fuzz heuristics library.

        Args:
            integer: int to append to fuzz heuristics
        """
        for i in range(-10, 10):
            case = integer + i
            # ensure the border case falls within the valid range for this field.
            if 0 <= case < self.max_num:
                if case not in self._mutations:
                    self._mutations.append(case)

    def _render(self, value: int):
        # TODO: Fix UnicodeDecodeError while rendering int.
        try:
            rendered = self.render_int(value, output_format=self.format, bit_width=self.width, endian=self.endian, signed=self.signed)
        except UnicodeDecodeError:
            rendered = self._original_value
        return rendered

    @staticmethod
    def render_int(value, output_format, bit_width, endian, signed):
        """
        Convert value to a bit or byte string.

        Args:
            value (int): Value to convert to a byte string.
            output_format (str): "binary" or "ascii"
            bit_width (int): Width of output in bits.
            endian: BIG_ENDIAN or LITTLE_ENDIAN
            signed (bool):

        Returns:
            str: value converted to a byte string
        """
        if output_format == "binary":
            bit_stream = ""
            rendered = b""

            # pad the bit stream to the next byte boundary.
            if bit_width % 8 == 0:
                bit_stream += int_to_binary_string(value, bit_width)
            else:
                bit_stream = "0" * (8 - (bit_width % 8))
                bit_stream += int_to_binary_string(value, bit_width)

            # convert the bit stream from a string of bits into raw bytes.
            for i in range(len(bit_stream) // 8):
                chunk_min = 8 * i
                chunk_max = chunk_min + 8
                chunk = bit_stream[chunk_min:chunk_max]
                # print(chunk)
                # print(struct.pack("B", binary_string_to_int(chunk)))
                rendered += struct.pack("B", binary_string_to_int(chunk))#.decode()

            # if necessary, convert the endianness of the raw bytes.
            if endian == LITTLE_ENDIAN:
                bytes_list = list(rendered)
                bytes_list.reverse()
                rendered = bytes(bytes_list)

            _rendered = rendered
        else:
            # Otherwise we have ascii/something else
            # if the sign flag is raised and we are dealing with a signed integer (first bit is 1).
            if signed and int_to_binary_string(value, bit_width)[0] == "1":
                max_num = binary_string_to_int("1" + "0" * (bit_width - 1))
                # chop off the sign bit.
                val = value & binary_string_to_int("1" * (bit_width - 1))

                # account for the fact that the negative scale works backwards.
                val = max_num - val - 1

                # toss in the negative sign.
                _rendered = "%d" % ~val

            # unsigned integer or positive signed integer.
            else:
                _rendered = "%d" % value
        if isinstance(_rendered, str):
            _rendered = _rendered.encode()
        return _rendered

    def __len__(self):
        if self.format == "binary":
            return self.width / 8
        else:
            return len(str(self._value))

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, self.render())


