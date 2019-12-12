import random
from ..mutant import Mutant


class RandomData(Mutant):
    def __init__(self, value: bytes, min_length: int, max_length: int, max_mutations: int = 25, fuzzable: bool = True,
                 step: int = None, name: str = None):
        """
        Generate a random chunk of data while maintaining a copy of the original. A random length range
        can be specified.
        For a static length, set min/max length to be the same.

        Args:
            value:          Original value
            min_length:     Minimum length of random block
            max_length:     Maximum length of random block
            max_mutations:  (Optional, def=25) Number of mutations to make before reverting to default
            fuzzable:       (Optional, def=True) Enable/disable fuzzing of this primitive
            step:           (Optional, def=None) If not null, step count between min and max reps, otherwise random
            name:           (Optional, def=None) Specifying a name gives you direct access to a primitive
        """
        self.min_length = min_length
        self.max_length = max_length
        self.max_mutations = max_mutations
        self.step = step
        if self.step:
            self.max_mutations = (self.max_length - self.min_length) / self.step + 1

        # Lets generate some random mutations
        mutations = []

        for _ in range(self.max_mutations):
            # select a random length for this string.
            if not self.step:
                length = random.randint(self.min_length, self.max_length)
            # select a length function of the mutant index and the step.
            else:
                length = self.min_length + self._mutant_index * self.step

            # reset the value and generate a random string of the determined length.
            self._value = b""
            for i in range(length):
                self._value += bytes([random.randint(0, 255)])

            mutations.append(self._value)

        # The Mutant behaviour is perfect for this one :)
        super().__init__(value, name=name, fuzzable=fuzzable, mutations=mutations)
