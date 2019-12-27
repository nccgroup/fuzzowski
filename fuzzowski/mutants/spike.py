"""
This file contains the typical SPIKE functions to create our Fuzzers.
"""
from typing import Iterable, List, Tuple, Union, TypeVar

from .mutant import Mutant
from ..exception import FuzzowskiRuntimeError
from . import blocks
from . import primitives
from ..constants import LITTLE_ENDIAN
from fuzzowski import responses

names_counter = {}


def _get_name_if_not_chosen(name: str, type_var: TypeVar) -> str:
    """ This function is used to automatically assign names to mutants (primitives and blocks) that do not have a
    name assigned.
    It uses the name_counter dict above to maintain a list of indexes
    """
    if name is None:
        names_counter[type_var] = names_counter.setdefault(type_var, 0) + 1
        classname = type_var.__name__.lower()
        name = f'{classname}{names_counter[type_var]}'
    return name

# ================================================================#
# REQUESTS                                                        #
# ================================================================#


def s_get(name: str = None) -> blocks.Request:
    """
    Return the request with the specified name or the current request if name is not specified. Use this to switch from
    global function style request manipulation to direct object manipulation. Example::

        req = s_get("HTTP BASIC")
        print req.num_mutations()

    The selected request is also set as the default current. (ie: s_switch(name) is implied).

    Args:
        name: (Optional, def=None) Name of request to return or current request if name is None.

    Returns:
        Request: The requested request.

    """
    if not name:
        return blocks.CURRENT

    # ensure this gotten request is the new current.
    s_switch(name)

    if name not in blocks.REQUESTS:
        raise FuzzowskiRuntimeError(f"REQUESTS NOT FOUND: {name}")

    return blocks.REQUESTS[name]

# --------------------------------------------------------------- #


def s_switch(name: str):
    """
    Change the current request to the one specified by "name".

    :type  name: str
    :param name: Name of request
    """

    if name not in blocks.REQUESTS:
        raise FuzzowskiRuntimeError("blocks.REQUESTS NOT FOUND: %s" % name)

    blocks.CURRENT = blocks.REQUESTS[name]

# --------------------------------------------------------------- #


def s_initialize(name: str):
    """
    Initialize a new block request. All blocks / primitives generated after this call apply to the named request.
    Use s_switch() to jump between factories.

    Args:
        name: Name of request
    """
    if name in blocks.REQUESTS:
        raise FuzzowskiRuntimeError("blocks.REQUESTS ALREADY EXISTS: %s" % name)

    blocks.REQUESTS[name] = blocks.Request(name)
    blocks.CURRENT = blocks.REQUESTS[name]

# --------------------------------------------------------------- #


def s_response(response_class: type, name: str, required_vars: List[str], optional_vars: List[str], *args, **kwargs):
    blocks.CURRENT.add_response(response_class(name, required_vars, optional_vars, *args, **kwargs))

# ================================================================#
# BLOCKS                                                          #
# ================================================================#

def s_block(name: str, group: str = None, encoder: callable = None,
            dep: str = None, dep_value: object = None, dep_values: List = None, dep_compare: str = "=="):
    """
    Open a new block under the current request. The returned instance supports the "with" interface so it will
    be automatically closed for you::

        with s_block("header"):
            s_static("\\x00\\x01")
            with s_block_start("body"):
                ...

    Args:
            name:           Name of the new block
            group:          Name of group to associate this block with
            encoder:        (Optional, def=None) Optional pointer to a function to pass rendered data to prior to return
            dep:            (Optional, def=None) Optional primitive whose specific value this block is dependant on
            dep_value:      (Optional, def=None) Value that field "dep" must contain for block to be rendered
            dep_values:     (Optional, def=[]) Values that field "dep" may contain for block to be rendered
            dep_compare:    (Optional, def="==") Comparison method to apply to dependency (==, !=, >, >=, <, <=)
    """

    # class ScopedBlock(Block):
    class ScopedBlock(object):
        def __init__(self, block_val):
            super().__init__()
            self.block = block_val

        def __enter__(self):
            """
            Setup before entering the "with" statement body
            """
            return self.block

        def __exit__(self, exc_type, value, traceback):
            """
            Cleanup after executing the "with" statement body
            """
            # Automagically close the block when exiting the "with" statement
            _s_block_end()

    block_ = _s_block_start(name, group, encoder, dep, dep_value, dep_values, dep_compare)

    return ScopedBlock(block_)

# --------------------------------------------------------------- #


def _s_block_start(name: str, *args, **kwargs):
    """
    Open a new block under the current request.
    with indenting::

        if s_block_start("header"):
            s_static("\\x00\\x01")
            if s_block_start("body"):
                ...
        s_block_close()

    :note Prefer using s_block to this function directly
    :see s_block
    """
    block_ = blocks.Block(name, blocks.CURRENT, *args, **kwargs)
    blocks.CURRENT.push(block_)

    return block_

# --------------------------------------------------------------- #


def _s_block_end():
    """
    Close the last opened block.
    """
    blocks.CURRENT.pop()

# --------------------------------------------------------------- #


def s_checksum(block_name: str, algorithm: Union[str, callable] = "crc32", output_format: str = "binary",
               length: int = 0, endian: chr = LITTLE_ENDIAN, fuzzable: bool = True, name: str = None,
               ipv4_src_block_name: str = None, ipv4_dst_block_name: str = None):
    """
    Create a checksum block bound to the block with the specified name. You *can not* create a checksum for any
    currently open blocks.

    Args:
        block_name:             Name of target block for checksum calculations.
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

    # you can't add a checksum for a block currently in the stack.
    if block_name in blocks.CURRENT.block_stack:
        raise FuzzowskiRuntimeError("CAN N0T ADD A CHECKSUM FOR A BLOCK CURRENTLY IN THE STACK")
    name = _get_name_if_not_chosen(name, blocks.Checksum)

    checksum = blocks.Checksum(block_name, blocks.CURRENT, algorithm, output_format, length, endian, fuzzable, name,
                               ipv4_src_block_name=ipv4_src_block_name,
                               ipv4_dst_block_name=ipv4_dst_block_name)
    blocks.CURRENT.push(checksum)

# --------------------------------------------------------------- #


def s_repeat(block_name: str, min_reps: int = 0, max_reps: int = None, step: int = 1, variable_name: str = None,
             include: bool = False, fuzzable: bool = True, name: str = None):
    """
    Repeat the rendered contents of the specified block cycling from min_reps to max_reps counting by step. By
    default renders to nothing. This block modifier is useful for fuzzing overflows in table entries. This block
    modifier MUST come after the block it is being applied to.

    Args:
        block_name:     Name of block to apply sizer to
        min_reps:       (Optional, def=0) Minimum number of block repetitions
        max_reps:       (Optional, def=None) Maximum number of block repetitions
        step:           (Optional, def=1) Step count between min and max reps
        variable_name:  (Optional, def=None) Repetitions will be derived from this variable name, disables fuzzing
        include:        (Optional, def=False) Consider the original block as the first repetition
                        (only used with variable_name) It has the limitation that can't erase the block!
        fuzzable:       (Optional, def=True) Enable/disable fuzzing of this primitive
        name:           (Optional, def=None) Specifying a name gives you direct access to a primitive

    """
    name = _get_name_if_not_chosen(name, blocks.Repeat)
    repeat = blocks.Repeat(block_name, blocks.CURRENT, min_reps=min_reps, max_reps=max_reps, step=step,
                           variable_name=variable_name, include=include, fuzzable=fuzzable, name=name)
    blocks.CURRENT.push(repeat)

# --------------------------------------------------------------- #


def s_size(block_name: str, offset: int = 0, length: int = 4,
           endian: chr = LITTLE_ENDIAN, output_format: str = "binary", inclusive: bool = False,
           signed: bool = False, math: callable = None, fuzzable: bool = True, name: str = None):
    """
    Create a sizer block bound to the block with the specified name. You *can not* create a sizer for any
    currently open blocks.

    :see: Aliases: s_sizer()

    Args:
            block_name:     Name of block to apply sizer to
            offset:         (Optional, def=4) Length of sizer
            length:         (Optional, def=0) Offset for calculated size value
            endian:         (Optional, def=LITTLE_ENDIAN) Endianess of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
            output_format:  (Optional, def=binary) Output format, "binary" or "ascii"
            inclusive:      (Optional, def=False) Should the sizer count its own length?
            signed:         (Optional, def=False) Make size signed vs. unsigned (applicable only with format="ascii")
            math:           (Optional, def=None) Apply the mathematical op defined in this function to the size
            fuzzable:       (Optional, def=True) Enable/disable fuzzing of this sizer
            name:           Name of this sizer field
    """

    # you can't add a size for a block currently in the stack.
    if block_name in blocks.CURRENT.block_stack:
        raise FuzzowskiRuntimeError("CAN NOT ADD A SIZE FOR A BLOCK CURRENTLY IN THE STACK")
    size = blocks.Size(
        block_name, blocks.CURRENT, offset, length, endian, output_format, inclusive, signed, math, fuzzable, name
    )
    blocks.CURRENT.push(size)


def s_variable(name: str, value: bytes, fuzzable: bool = False):
    """
    A variable that takes the value of a variable set in the request

    Args:
        name:       Name of the variable block, it is also used to set the variable
        value:      Default value if the variable is not set
        fuzzable:   (Optional, def=False) Enable/disable fuzzing of this primitive
    """
    variable = blocks.Variable(name, blocks.CURRENT, value, fuzzable)
    blocks.CURRENT.push(variable)


# ================================================================#
# PRIMITIVES                                                      #
# ================================================================#


def s_static(value: bytes, name: str = None):
    """
    Push a static value onto the current block stack.

    :see: Aliases: s_dunno(), s_raw(), s_unknown()

    Args:
        value: The static value
        name:  (Optional, def=None) The name of the primitive

    """
    name = _get_name_if_not_chosen(name, primitives.Static)
    static = primitives.Static(value, name)
    blocks.CURRENT.push(static)

# --------------------------------------------------------------- #


def s_string(value: Union[str, bytes], name: str = None, size: int = -1, padding: Union[str, bytes] = "\x00",
             encoding: str = "utf-8", fuzzable: bool = True, max_len: int = -1, callback_addr: str = None,
             filename: str = None, mutation_types: Iterable = primitives.String.default_mutation_types):

    """
    Push a string onto the current block stack.

    Args:
        value:          Original string value
        name:           Primitive name
        size:           (Optional, def=-1) Static size of this field, leave -1 for dynamic.
        padding:        (Optional, def="\\x00") Value to use as padding to fill static field size.
        encoding:       (Optional, def="utf-8") String encoding, ex: utf_16_le for Microsoft Unicode.
        fuzzable:       (Optional, def=True) Enable/disable fuzzing of this primitive
        max_len:        (Optional, def=-1) Maximum string length
        callback_addr:  (Optional, def=None) Specifying a callback addr will inject ping and nslookup commands
        filename:       (Optional, def=None) Specifying a filename will replace mutations with the filename ones
        mutation_types: (Optional, def=('instance', 'callback', 'file', 'long', 'commands', 'format', 'misc'))
                        Types of mutations to use for this String:
                            instance: Specific mutations based in the default value
                            callbacks: nslookup and ping comand injection with callbacks (callback_addr must be set)
                            file: mutations obtained from file (filename must be set)
                            long: Long strings
                            command: command injection strings
                            format: format strings
                            misc: other mutations
    """
    name = _get_name_if_not_chosen(name, primitives.String)
    s = primitives.String(value, size=size, padding=padding, encoding=encoding, fuzzable=fuzzable, max_len=max_len,
                          name=name, callback_addr=callback_addr, filename=filename, mutation_types=mutation_types)
    blocks.CURRENT.push(s)

# --------------------------------------------------------------- #


def s_mutant(value: bytes, name: str = None, fuzzable: bool = True, mutations: list = None):

    """
    Push a basic mutant with the selected mutations into the block stack

    Args:
        value: The original value
        name: Name of the Mutant Element
        fuzzable: True if it is fuzzable
        mutations: List of mutations
    """
    name = _get_name_if_not_chosen(name, Mutant)
    m = Mutant(value, name=name, fuzzable=fuzzable, mutations=mutations)
    blocks.CURRENT.push(m)


# --------------------------------------------------------------- #


def s_bit_field(value: int, width: int, max_num: int = None,
                endian: chr = LITTLE_ENDIAN, output_format: str = "binary", signed: bool = False,
                full_range: bool = False, fuzzable: bool = True, name: str = None,
                mutations: Union[List[int], Tuple[int]] = ()):
    """
    Push a variable length bit field onto the current block stack.

    :see: Aliases: s_bit(), s_bits()

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
    name = _get_name_if_not_chosen(name, primitives.BitField)
    # bit_field = primitives.BitField(value, width, None, endian, output_format, signed, full_range, fuzzable, name)
    bit_field = primitives.BitField(value, width, max_num=max_num, endian=endian, output_format=output_format,
                                    signed=signed, full_range=full_range, fuzzable=fuzzable, name=name,
                                    mutations=mutations)
    blocks.CURRENT.push(bit_field)

# --------------------------------------------------------------- #


def s_byte(value, endian=LITTLE_ENDIAN, output_format="binary", signed=False, full_range=False, fuzzable=True,
           name=None, mutations=()):
    """
    Push a byte onto the current block stack.

    :see: Aliases: s_char()

    Args:
        value:          Default integer value
        endian:         (Optional, def=LITTLE_ENDIAN) Endianess of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
        output_format:  (Optional, def=binary) Output format, "binary" or "ascii"
        signed:         (Optional, def=False) Make size signed vs. unsigned (applicable only with format="ascii")
        full_range:     (Optional, def=False) If enabled the field mutates through *all* possible values.
        fuzzable:       (Optional, def=True) Enable/disable fuzzing of this primitive
        name:           (Optional, def=None) Specifying a name gives you direct access to a primitive
        mutations:      (Optional, def=()) Specify the list of mutations to override the default ones
    """
    name = _get_name_if_not_chosen(name, primitives.Byte)
    byte = primitives.Byte(value, endian=endian, output_format=output_format, signed=signed, full_range=full_range,
                           fuzzable=fuzzable, name=name, mutations=mutations)
    blocks.CURRENT.push(byte)

# --------------------------------------------------------------- #


def s_word(value, endian=LITTLE_ENDIAN, output_format="binary", signed=False, full_range=False, fuzzable=True,
           name=None, mutations=()):
    """
    Push a word onto the current block stack. Word is a 2 Bytes sized BitField

    :see: Aliases: s_short()

    Args:
        value:          Default integer value
        endian:         (Optional, def=LITTLE_ENDIAN) Endianess of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
        output_format:  (Optional, def=binary) Output format, "binary" or "ascii"
        signed:         (Optional, def=False) Make size signed vs. unsigned (applicable only with format="ascii")
        full_range:     (Optional, def=False) If enabled the field mutates through *all* possible values.
        fuzzable:       (Optional, def=True) Enable/disable fuzzing of this primitive
        name:           (Optional, def=None) Specifying a name gives you direct access to a primitive
        mutations:      (Optional, def=()) Specify the list of mutations to override the default ones
    """
    name = _get_name_if_not_chosen(name, primitives.Word)
    word = primitives.Word(value, endian=endian, output_format=output_format, signed=signed, full_range=full_range,
                           fuzzable=fuzzable, name=name, mutations=mutations)
    blocks.CURRENT.push(word)

# --------------------------------------------------------------- #


def s_dword(value, endian=LITTLE_ENDIAN, output_format="binary", signed=False, full_range=False, fuzzable=True,
            name=None, mutations=()):
    """
    Push a double word onto the current block stack. DWord is a 4 Bytes sized BitField

    :see: Aliases: s_long(), s_int()

    Args:
        value:          Default integer value
        endian:         (Optional, def=LITTLE_ENDIAN) Endianess of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
        output_format:  (Optional, def=binary) Output format, "binary" or "ascii"
        signed:         (Optional, def=False) Make size signed vs. unsigned (applicable only with format="ascii")
        full_range:     (Optional, def=False) If enabled the field mutates through *all* possible values.
        fuzzable:       (Optional, def=True) Enable/disable fuzzing of this primitive
        name:           (Optional, def=None) Specifying a name gives you direct access to a primitive
        mutations:      (Optional, def=()) Specify the list of mutations to override the default ones
    """
    name = _get_name_if_not_chosen(name, primitives.DWord)
    dword = primitives.DWord(value, endian=endian, output_format=output_format, signed=signed, full_range=full_range,
                             fuzzable=fuzzable, name=name, mutations=mutations)
    blocks.CURRENT.push(dword)

# --------------------------------------------------------------- #


def s_qword(value, endian=LITTLE_ENDIAN, output_format="binary", signed=False, full_range=False, fuzzable=True,
            name=None, mutations=()):
    """
    Push a quad word onto the current block stack.

    :see: Aliases: s_double()

    Args:
        value:          Default integer value
        endian:         (Optional, def=LITTLE_ENDIAN) Endianess of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
        output_format:  (Optional, def=binary) Output format, "binary" or "ascii"
        signed:         (Optional, def=False) Make size signed vs. unsigned (applicable only with format="ascii")
        full_range:     (Optional, def=False) If enabled the field mutates through *all* possible values.
        fuzzable:       (Optional, def=True) Enable/disable fuzzing of this primitive
        name:           (Optional, def=None) Specifying a name gives you direct access to a primitive
        mutations:      (Optional, def=()) Specify the list of mutations to override the default ones
    """
    name = _get_name_if_not_chosen(name, primitives.QWord)
    qword = primitives.QWord(value, endian=endian, output_format=output_format, signed=signed, full_range=full_range,
                             fuzzable=fuzzable, name=name, mutations=mutations)
    blocks.CURRENT.push(qword)


# --------------------------------------------------------------- #


def s_delim(value: bytes, fuzzable: bool = True, name: str = None):
    """
    Push a delimiter onto the current block stack.
    Represent a delimiter such as :,\r,\n, ,=,>,< etc... Mutations include repetition, substitution and exclusion.

    Args:
        value:      Original value
        fuzzable:   (Optional, def=True) Enable/disable fuzzing of this primitive
        name:       (Optional, def=None) Specifying a name gives you direct access to a primitive
    """
    name = _get_name_if_not_chosen(name, primitives.Delim)
    delim = primitives.Delim(value, fuzzable, name)
    blocks.CURRENT.push(delim)


# --------------------------------------------------------------- #


def s_group(value: bytes, values: List[bytes], name: str = None):
    name = _get_name_if_not_chosen(name, primitives.Group)
    group = primitives.Group(value, values, name=name)
    blocks.CURRENT.push(group)

# def s_from_file(value, encoding="utf-8", fuzzable=True, max_len=0, name=None, filename=None):
#     """
#     Push a value from file onto the current block stack.
#
#     :type  value:    str
#     :param value:    Default string value
#     :type  encoding: str
#     :param encoding: (Optonal, def="ascii") String encoding, ex: utf_16_le for Microsoft Unicode.
#     :type  fuzzable: bool
#     :param fuzzable: (Optional, def=True) Enable/disable fuzzing of this primitive
#     :type  max_len:  int
#     :param max_len:  (Optional, def=0) Maximum string length
#     :type  name:     str
#     :param name:     (Optional, def=None) Specifying a name gives you direct access to a primitive
#     :type  filename: str
#     :param filename: (Mandatory) Specify filename where to read fuzz list
#     """
#
#     s = primitives.FromFile(value, encoding, fuzzable, max_len, name, filename)
#     blocks.CURRENT.push(s)

# --------------------------------------------------------------- #

# ALIASES


s_int = s_dword
# s_long = s_int = s_dword
# For now I'm not going to have them
# s_dunno = s_raw = s_unknown = s_static
# s_sizer = s_size
# s_bit = s_bits = s_bit_field
# s_char = s_byte
# s_short = s_word
# s_double = s_qword
# s_repeater = s_repeat
