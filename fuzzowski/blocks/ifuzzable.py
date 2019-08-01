import abc


class IFuzzable(object):
    """Describes a fuzzable message element or message.

    Design Notes:
     - mutate and reset pretty much form an iterator. Future design goal is
       to eliminate them and add a generator function in their place.
    """

    @abc.abstractmethod
    def fuzzable(self):
        """If False, this element should not be mutated in normal fuzzing."""
        return

    @abc.abstractmethod
    def mutant_index(self):
        """Index of current mutation. 0 => normal value. 1 => first mutation.
        """
        return

    @abc.abstractmethod
    def original_value(self):
        """Original, non-mutated value of element."""
        return

    @abc.abstractmethod
    def disabled(self):
        """Return if the element is disabled"""
        return

    @abc.abstractmethod
    def name(self):
        """Element name, should be specific for each instance."""
        return

    @abc.abstractmethod
    def mutate(self):
        """Mutate this element. Returns True each time and False on completion.

        Use reset() after completing mutations to bring back to original state.

        Mutated values available through render().

        Returns:
            bool: True if there are mutations left, False otherwise.
        """
        return

    @abc.abstractmethod
    def num_mutations(self):
        """Return the total number of mutations for this element.

        Returns:
            int: Number of mutated forms this primitive can take
        """
        return

    @abc.abstractmethod
    def render(self, replace_node=None, replace_value=None, original=False):
        """Return rendered value. Equal to original value after reset().
        If replace_node and replace_value are set, if the node name is the same as self.name(),
        it should return the replace_value instead
        if original is True, it will return the original value instead of the rendered value
        """

        # if replace_node is not None and replace_value is not None and replace_node == self.name:
        #     self._rendered = replace_value
        #     return self._rendered

        return

    @abc.abstractmethod
    def reset(self):
        """Reset element to pre-mutation state."""
        return

    @abc.abstractmethod
    def __repr__(self):
        return

    @abc.abstractmethod
    def __len__(self):
        """Length of field. May vary if mutate() changes the length.

        Returns:
            int: Length of element (length of mutated element if mutated).
        """
        return

    @abc.abstractmethod
    def __nonzero__(self):
        """Make sure instances evaluate to True even if __len__ is zero.

        Design Note: Exists in case some wise guy uses `if my_element:` to
        check for null value.

        Returns:
            bool: True
        """
        return
