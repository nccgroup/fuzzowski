from typing import List, Optional

from ..mutant import Mutant
from .request import Request


class Callable(Mutant):
    def __init__(self, request: Request, value: bytes, function: callable, var_args: Optional[List[str]] = None,
                 fuzzable: bool = False, name: str = None, *args, **kwargs):
        """
        Block that calculates the value with a function passed as argument

        Args:
            request:    Request this variable block belongs to
            value:      Default value to calculate lengths
            function:   function to be executed
            var_args:   list of variables to be obtained and passed to the function as kwargs
            fuzzable:   (Optional, def=False) Enable/disable fuzzing of this primitive
            name:       Name of the variable block, it is also used to set the variable
            *args:      Arguments to be passed to the function
            **kwargs:   Named arguments to be passed to the function
        """

        super().__init__(value, name, fuzzable)
        self._name = name
        self.request = request
        self.function = function
        self.var_args = var_args
        self.args = args
        self.kwargs = kwargs

    def render(self, replace_node: str = None, replace_value: bytes = None, original: bool = False) -> bytes:
        if self.var_args is not None:
            var_kwargs = {}
            for var in self.var_args:
                var_kwargs[var] = self.request.variables.get(var)
            return self.function(**var_kwargs)
        elif len(self.args) > 0 or len(self.kwargs) > 0:
            return self.function(*self.args, **self.kwargs)
        else:
            return self._value

    """
    @property
    def original_value(self) -> bytes:
        return self.render()
    """