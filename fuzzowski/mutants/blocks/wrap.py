from ..mutant import Mutant


class Wrap(Mutant):

    def __init__(self, value: bytes, prefix: bytes, suffix: bytes, min_reps: int, max_reps: int,
                 step: int = 1, fuzzable: bool = True, name: str = None):
        """
        Wrap the contents of the specified value repeating the prefix and suffix from min_reps to max_reps counting by step. By
        default renders to value. This modifier can be useful to find bugs with recursive functions.

        Args:
            value:          String value
            prefix:         Value to add before the value
            suffix:         Value to add after the value
            min_reps:       Minimum number of block repetitions
            max_reps:       Maximum number of block repetitions
            step:           (Optional, def=1) Step count between min and max reps
            fuzzable:       (Optional, def=True) Enable/disable fuzzing of this primitive
            name:           (Optional, def=None) Specifying a name gives you direct access to a primitive
        """

        mutations = [ num_repeats*prefix + value + num_repeats*suffix for num_repeats
                     in range(min_reps, max_reps + 1, step)]

        super().__init__(value, name, fuzzable, mutations=mutations)

