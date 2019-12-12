from abc import ABCMeta, abstractmethod
from typing import Generator


class IMutant(object, metaclass=ABCMeta):
    """
    Generic Mutant Interface. Defines all public methods that should be overridden
    """

    @abstractmethod
    def __init__(self):
        """
        Initializes the Mutant class, most Primitives and Blocks should override this
        """
        pass

    @abstractmethod
    def __iter__(self):
        pass

    @abstractmethod
    def __next__(self):
        pass

    @abstractmethod
    def __repr__(self):
        pass

    @abstractmethod
    def __len__(self):
        """
        Length of field. May vary if mutate() changes the length.

        Returns:
            int: Length of element (length of mutated element if mutated).
        """
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Element name, should be specific for each instance.

        Returns:
            str: Name of the mutant
        """
        pass

    @property
    @abstractmethod
    def original_value(self) -> bytes:
        """
        Original value of the element without any fuzzing

        Returns:
            bytes: Original value
        """
        pass

    @property
    @abstractmethod
    def mutant_index(self) -> int:
        """
        Index of current mutation. 0 => original value. 1 => first mutation.

        Returns:
            int: Index of current mutation
        """
        pass

    @property
    @abstractmethod
    def num_mutations(self) -> int:
        """
        Total number of mutations for this element.

        Returns:
            int: Number of mutated forms this primitive can take
        """
        pass

    @property
    @abstractmethod
    def fuzzable(self) -> bool:
        """
        If False, this element should not be mutated in normal fuzzing.

        Returns:
            bool: If the element is fuzzable or not
        """
        pass

    @property
    @abstractmethod
    def disabled(self) -> bool:
        """
        If disabled, the mutations should be discarded
        Returns:
            bool: If the mutant was disabled or not
        """
        pass

    @disabled.setter
    @abstractmethod
    def disabled(self, value: bool):
        """
        Setter for disabled

        Args:
            value (bool): True or False
        """
        pass

    @abstractmethod
    def mutation_generator(self, mutant_index: int = 0) -> Generator[bytes, None, None]:
        """
        Creates a generator that will change the Mutant and return the mutated value

        Args:
            mutant_index: It initializes the mutant_index at the specified value

        Returns:
            Generator: The mutations generator
        """
        pass

    @abstractmethod
    def goto(self, mutant_index: int):
        """
        Moves the state of the mutant to the specified mutant_index

        Args:
            mutant_index (int): The mutant_index
        """
        pass

    @abstractmethod
    def render(self, replace_node: str = None, replace_value: str = None, original: bool = False) -> bytes:
        """
        Renders the value of the actual state

        Args:
            replace_node: If replace node is set, instead of the value it will use the replace_value
            replace_value: Value to be used
            original: If the original value is to be used instead of the actual value TODO: Is this necessary?

        Returns:
            bytes: The rendered value
        """
        pass

    @abstractmethod
    def reset(self):
        """Reset element to pre-mutation state."""
        pass
