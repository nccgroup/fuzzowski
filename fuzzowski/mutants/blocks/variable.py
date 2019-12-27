from ..mutant import Mutant
from .request import Request
# from . import VARIABLES


class Variable(Mutant):
    def __init__(self, name: str, request: Request, value: bytes, fuzzable: bool = False):
        """
        A variable that takes the value of a variable set in the request

        Args:
            name:       Name of the variable block, it is also used to set the variable
            request:    Request this variable block belongs to
            value:      Default value if the variable is not set
            fuzzable:   (Optional, def=False) Enable/disable fuzzing of this primitive
        """

        # TODO: Add all fuzzing! For example, add "type" to convert the variable in other primitive (e.g. String)
        #  and inherit the mutations?

        super().__init__(value, name, fuzzable)
        self._name = name
        self.request = request

    def render(self, replace_node: str = None, replace_value: bytes = None, original: bool = False) -> bytes:
        if self._name in self.request.variables:
            return self.request.variables[self._name]
            # return VARIABLES[self._name]
        else:
            return self._value

    @property
    def original_value(self) -> bytes:
        if self._name in self.request.variables:
            return self.request.variables[self._name]
            # return VARIABLES[self._name]
        else:
            return self._render(self._original_value)
