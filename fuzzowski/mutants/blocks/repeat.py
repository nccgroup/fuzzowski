from fuzzowski.exception import FuzzowskiRuntimeError
from fuzzowski.mutants.primitives import BitField
from ..mutant import Mutant


class Repeat(Mutant):

    def __init__(self, block_name: str, request: 'Request', min_reps: int = 0, max_reps: int = None,
                 step: int = 1, variable_name: str = None, include: bool = False, fuzzable: bool = True, name: str = None):
        """
        Repeat the rendered contents of the specified block cycling from min_reps to max_reps counting by step. By
        default renders to nothing. This block modifier is useful for fuzzing overflows in table entries. This block
        modifier MUST come after the block it is being applied to.

        Args:
            block_name:     Name of block to apply sizer to
            request:        Request this block belongs to
            min_reps:       (Optional, def=0) Minimum number of block repetitions
            max_reps:       (Optional, def=None) Maximum number of block repetitions
            step:           (Optional, def=1) Step count between min and max reps
            variable_name:  (Optional, def=None) Repetitions will be derived from this variable name, disables fuzzing
            include:        (Optional, def=False) Consider the original block as the first repetition
                            (only used with variable_name) It has the limitation that can't erase the block!
            fuzzable:       (Optional, def=True) Enable/disable fuzzing of this primitive
            name:           (Optional, def=None) Specifying a name gives you direct access to a primitive
        """
        super().__init__(b'', name, fuzzable)
        self.block_name = block_name
        self.request = request
        self.min_reps = min_reps
        self.max_reps = max_reps
        self.step = step
        self.variable = None
        self.include = include

        # ensure the target block exists.
        if self.block_name not in self.request.names:
            raise FuzzowskiRuntimeError(
                "Can't add repeater for non-existent block: %s!" % self.block_name
            )
        self.block = self.request.names[self.block_name]  # Save target block to repeat

        # ensure the target variable_name exists.
        if variable_name is not None:
            if variable_name not in self.request.names:
                raise FuzzowskiRuntimeError(
                    "Can't add repeater for non-existent variable: %s!" % self.block_name
                )
            self.variable = self.request.names[variable_name]  # Save target block to repeat

        # if a variable is specified, ensure it is an integer type.
        if self.variable and not isinstance(self.variable, BitField):
            print(self.variable)
            raise FuzzowskiRuntimeError(
                "Attempt to bind the repeater for block %s to a non-integer primitive!" % self.block_name
            )

        # ensure the user specified either a variable to tie this repeater to or a min/max val.
        if self.variable is None and self.max_reps is None:
            raise FuzzowskiRuntimeError(
                "Repeater for block %s doesn't have a min/max or variable binding!" % self.block_name
            )

        # if not binding variable was specified, propagate the fuzz library with the repetition counts.
        if not self.variable:
            self._mutations = range(self.min_reps, self.max_reps + 1, self.step)
        # otherwise, disable fuzzing as the repetition count is determined by the variable.
        else:
            self._fuzzable = False
        self._disabled = False

    def _mutate(self):
        """
        Modifies the Mutant
        Set the mutant to the next mutation, increasing the mutant_index and upgrading the value
        Returns: True if it was mutated correctly, false if there are no mutations left or the mutant is
        """
        ret_value = super()._mutate()

        if ret_value is True:
            # If the variable is set, it will repeat variable times
            if self.variable:
                num_repeats = max(0, self.variable._value - 1) if self.include else self.variable._value
                self._value = num_repeats * self.block.render()
            else:
                num_repeats = self._value  # Mutate will take self._mutations[self.mutant_index]
                self._value = num_repeats * self.block.render()

        return ret_value

    def render(self, replace_node: str = None, replace_value: bytes = None, original: bool = False) -> bytes:
        """
        Nothing fancy on render, simply return the value.
        """
        if replace_node is not None and replace_value is not None and replace_node == self.name:
            self._rendered = replace_value
        elif original is True:
            self._rendered = self._original_value
        elif self.variable:
            num_repeats = max(0, self.variable._value - 1) if self.include else self.variable._value
            self._value = self.block.render() * num_repeats
            self._rendered = self._render(self._value)
        else:
            self._rendered = self._render(self._value)

        return self._rendered