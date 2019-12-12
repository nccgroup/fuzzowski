from typing import List

from ..mutant import Mutant


class Group(Mutant):
    def __init__(self, value: bytes, values: List[bytes], name: str = None):
        """
        This primitive represents a list of static values, stepping through each one on mutation. You can tie a block
        to a group primitive to specify that the block should cycle through all possible mutations for *each* value
        within the group. The group primitive is useful for example for representing a list of valid opcodes.

        Args:
            value: The default value
            values: The list of possible values (a list of bytes)
            name: The name of the group
        """
        # A group is basically a mutant with predefined values :)
        super().__init__(value, name=name, fuzzable=True, mutations=values)
