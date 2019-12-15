from ..exception import FuzzowskiRuntimeError
from .imutant import IMutant
from typing import Generator, Union
import re


class Mutant(IMutant):
    """
    Generic Mutant Class, Primitives and blocks should inherit from this and
    """

    name_re = re.compile('^[A-Za-z0-9_]+$')

    def __init__(self, value: bytes, name: str = None, fuzzable: bool = True, mutations: list = None):
        """
        Initializes the Mutant class, most Primitives and Blocks should override this

        Args:
            value: The original value
            name: Name of the Mutant Element
            fuzzable: True if it is fuzzable
            mutations: List of mutations
        """
        super().__init__()

        if mutations is None:
            mutations = []
        self._fuzzable = fuzzable  # flag controlling whether or not the given mutant is to be fuzzed.
        self.name = name
        self._mutations = mutations  # library of static fuzz heuristics to cycle through.
        self._rendered = ""  # rendered value of primitive.

        self._original_value = value  # original value of primitive.

        # These 3 values are set by reset() to these values
        if self._fuzzable:
            self._fuzz_complete = False  # this flag is raised when the mutations are exhausted
        else:
            self._fuzz_complete = True
        self._value = self._original_value  # current value of primitive.
        self._mutant_index = 0  # current mutation index into the fuzz library.

        self._disabled = False  # If the node is _disabled, its mutations should not be used
        self._mutation_gen = self.mutation_generator()

    def __iter__(self):
        self.reset()
        self._mutation_gen = self.mutation_generator()
        return self

    def __next__(self):
        return next(self._mutation_gen)

    def __repr__(self):
        return f'<{self.__class__.__name__} {self.name} = {repr(self._value)}>'

    def __len__(self):
        """
        Returns the length of the actual mutation
        Returns: The length of the actual mutation
        """
        return len(self._value)

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, value: str):
        if value is not None and self.name_re.match(value):
            self._name = value
        else:
            raise FuzzowskiRuntimeError(f'Invalid name: "{value}". '
                                        f'Name must follow the following pattern: {self.name_re.pattern}')

    @property
    def fuzzable(self) -> bool:
        return self._fuzzable

    @property
    def disabled(self) -> bool:
        return self._disabled

    @disabled.setter
    def disabled(self, value: bool):
        self._disabled = value

    @property
    def mutant_index(self) -> int:
        return self._mutant_index

    @property
    def num_mutations(self) -> int:
        return len(self._mutations) if self._fuzzable else 0

    @property
    def original_value(self) -> bytes:
        return self._render(self._original_value)

    def reset(self):
        """
        Resets the mutant to the original state
        Returns: None
        """
        if self._fuzzable:
            self._fuzz_complete = False  # this flag is raised when the mutations are exhausted
        else:
            self._fuzz_complete = True
        self._mutant_index = 0  # current mutation index into the fuzz library.
        self._value = self._original_value  # current value of primitive.

    def _mutate(self):
        """
        Set the mutant to the next mutation, increasing the mutant_index and upgrading the value
        Returns: True if it was mutated correctly, false if there are no mutations left or the mutant is
        """
        # if we've ran out of mutations, raise the completion flag.
        if self.mutant_index == self.num_mutations:
            self._fuzz_complete = True

        # if fuzzing was _disabled or complete, and _mutate() is called, ensure the original value is restored.
        if not self._fuzzable or self._fuzz_complete:
            self._value = self._original_value
            self.reset()
            return False

        # update the current value from the fuzz library.
        self._value = self._mutations[self.mutant_index]

        # increment the mutation count.
        self._mutant_index += 1

        return True

    def mutation_generator(self, mutant_index: int = 0) -> Generator[bytes, None, None]:
        if mutant_index is not None:
            self.reset()
            self.goto(mutant_index)
        return self._mutation_generator()

    def _mutation_generator(self):
        # if self.mutant_index != 0:
        #     yield self.render()  # We want to render the first value of the generator when we go with goto
        while self._mutate():
            yield self.render()

    def goto(self, mutant_index: int):
        if mutant_index > self.num_mutations:
            raise FuzzowskiRuntimeError(f"Mutant tried to get mutation "
                                        f"{mutant_index} > num_mutations ({self.num_mutations})")
        elif mutant_index == 0:
            self.reset()
        else:
            self._mutant_index = mutant_index - 1
            self._mutate()

    def render(self, replace_node: str = None, replace_value: bytes = None, original: bool = False) -> bytes:
        """
        Nothing fancy on render, simply return the value.
        """
        if replace_node is not None and replace_value is not None and replace_node == self.name:
            self._rendered = replace_value
        elif original is True:
            self._rendered = self._original_value
        else:
            self._rendered = self._render(self._value)

        return self._rendered

    def _render(self, value: Union[bytes, str]) -> bytes:
        """
        Render an arbitrary value.

        Args:
            value: Value to render.

        Returns:
            bytes: Rendered value
        """
        if isinstance(value, bytes):
            _rendered = value
        else:
            _rendered = value.encode()  # render always to bytes
        return _rendered
