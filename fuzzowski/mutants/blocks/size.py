from functools import wraps
from ...constants import LITTLE_ENDIAN
from ..primitives.bit_field import BitField
from ..blocks.request import Request


def _may_recurse(f):
    @wraps(f)
    def safe_recurse(self, *args, **kwargs):
        self._recursion_flag = True
        result = f(self, *args, **kwargs)
        self._recursion_flag = False
        return result

    return safe_recurse


class Size(BitField):

    def __init__(self, block_name: str, request: Request, offset: int = 0, length: int = 4,
                 endian: chr = LITTLE_ENDIAN, output_format: str = "binary", inclusive: bool = False,
                 signed: bool = False, math: callable = None, fuzzable: bool = True, name: str = None):
        """
        Create a sizer block bound to the block with the specified name. Size blocks that size their own parent or
        grandparent are allowed.

        Args:
            block_name:     Name of block to apply sizer to
            request:        Request this block belongs to
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
        # Initialize the BitField!
        self.length = length
        super().__init__(0, self.length * 8,
                         endian=endian,
                         output_format=output_format,
                         signed=signed,
                         fuzzable=fuzzable)

        self.block_name = block_name
        self.request = request
        self.offset = offset
        self.inclusive = inclusive
        self.math = math
        self._name = name
        if self._name is None:
            self._name = 'size_{}'.format(self.block_name)

        # self._disabled = False
        self._rendered = b""
        self._fuzz_complete = False

        if not self.math:
            self.math = lambda p: p

        # Set the recursion flag before calling a method that may cause a recursive loop.
        self._recursion_flag = False

    def render(self, replace_node: str = None, replace_value: bytes = None, original: bool = False) -> bytes:
        """
        Render the sizer.

        :return: Rendered value.
        """
        # Code for when we need the replace_value instead of the original_value
        if replace_node is not None and replace_value is not None:
            if replace_node == self.name:
                self._rendered = replace_value
                return self._rendered
            elif replace_node == self.block_name:
                self._rendered = self._render_replaced_value(replace_value)
                return self._rendered
            elif original is True:
                self._rendered = self.original_value
                return self._rendered

        # Rest of the cases
        if self._fuzzable and (self.mutant_index != 0) and not self._fuzz_complete:
            # In this case, we render the mutated value
            self._rendered = self._render(self._value)
        elif self._recursion_flag:  # If activated, we are in a recursion loop so we need to stop it
            # We are rendering a block which includes the size to just get the size, so give a dummy for the length!
            self._rendered = self._get_dummy_value()
        else:
            # Otherwise, render the size of the destination block!
            self._rendered = self._render(self._calculated_length())

        return self._rendered

    def _render_replaced_value(self, replaced_value: bytes) -> bytes:
        """
        Render the length of the replaced_value passed as argument, taking other parameters into account
        Args:
            replaced_value: value to calculate the length

        Returns: The length in rendered format of the replaced_value

        """
        length = self.offset + self._inclusive_length_of_self + len(replaced_value)
        return self._render(length)

    @property
    def _inclusive_length_of_self(self) -> int:
        """
        Returns: the length of self or zero if inclusive flag is False.
        """
        if self.inclusive:
            return self.length
        else:
            return 0

    def _calculated_length(self) -> int:
        """
        Returns: The length of the target block, taking the parameters into account
        """
        return self.offset + self._inclusive_length_of_self + self._length_of_target_block

    @property
    @_may_recurse
    def _length_of_target_block(self) -> int:
        """
        Calculate the length of target block, including mutations if it is currently mutated.

        Returns: the length of the actual mutation of the target block
        """
        # length = len(self.request.names[self.block_name])
        length = len(self.request.get_mutant(self.block_name))
        return length

    @property
    def original_value(self):
        length = self._original_calculated_length()
        return self._render(length)

    def _original_calculated_length(self):
        return self.offset + self._inclusive_length_of_self + self._original_length_of_target_block

    @property
    @_may_recurse
    def _original_length_of_target_block(self) -> int:
        """
        Calculates the length of original value of the target block.

        Returns: the length of the original_value of the target block
        """
        # length = len(self.request.names[self.block_name].original_value)
        length = len(self.request.get_mutant(self.block_name).original_value)

        return length

    def _get_dummy_value(self) -> bytes:
        """
        Return a dummy value, for the cases when we enter in a recursion loop while rendering to calculate lengths

        Returns: A dummy value
        """
        # TODO: If the output_format is ascii this could render a wrong size?
        return self.length * b'\x00'

    def __len__(self) -> int:
        return len(self.render())
        # return self.length

    # @property
    # def original_value(self):
    #     length = self._original_calculated_length()
    #     return self._length_to_bytes(length)
    #

    #
    # def _length_to_bytes(self, length):
    #     return BitField.render_int(value=self.math(length),
    #                                output_format=self.format,
    #                                bit_width=self.length * 8,
    #                                endian=self.endian,
    #                                signed=self.signed)
    #
    # def render(self, replace_node=None, replace_value=None, original=False):
    #     """
    #     Render the sizer.
    #
    #     :return: Rendered value.
    #     """
    #
    #     if replace_node is not None and replace_value is not None:
    #         if replace_node == self.name:
    #             self._rendered = replace_value
    #             return self._rendered
    #         elif replace_node == self.block_name:
    #             self._rendered = self._render_replaced_value(replace_value)
    #             return self._rendered
    #         elif original is True:
    #             self._rendered = self.original_value
    #             return self._rendered
    #
    #     if self._should_render_fuzz_value():
    #         self._rendered = self.render()
    #     elif self._recursion_flag:
    #         self._rendered = self._get_dummy_value()
    #     else:
    #         self._rendered = self._render_size()
    #
    #     return self._rendered
    #
    # def _should_render_fuzz_value(self):
    #     return self._fuzzable and (self.mutant_index != 0) and not self._fuzz_complete
    #

    #
    # def _render_size(self):
    #     length = self._calculated_length()
    #     return self._length_to_bytes(length)
    #
    # def _render_replaced_value(self, replaced_value):
    #     length = self.offset + self._inclusive_length_of_self + len(replaced_value)
    #     return self._length_to_bytes(length)
    #
    # def _calculated_length(self):
    #     return self.offset + self._inclusive_length_of_self + self._length_of_target_block
    #

    # @property
    # @_may_recurse
    # def _length_of_target_block(self):
    #     """Return length of target block, including mutations if it is currently mutated."""
    #     length = len(self.request.names[self.block_name])
    #     return length
    #
    # @property
    # @_may_recurse
    # def _original_length_of_target_block(self):
    #     """Return length of target block, including mutations if it is currently mutated."""
    #     length = len(self.request.names[self.block_name].original_value)
    #     return length

    # def __len__(self):
    #     return self.length
