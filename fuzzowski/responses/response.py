import pprint
from typing import List, Mapping
from abc import ABCMeta, abstractmethod

from fuzzowski.exception import FuzzowskiRuntimeError
from fuzzowski.mutants import blocks


class Response(object, metaclass=ABCMeta):
    """The Response object contains methods to parse the request, set the variables found and print the response"""
    def __init__(self, name: str, required_vars: List[str], optional_vars: List[str]):
        self.name = name
        self.required_vars = required_vars
        self.optional_vars = optional_vars
        self.vars: Mapping[str, bytes] = dict()

    @abstractmethod
    def _extract_variables(self, data: bytes) -> Mapping[str, bytes]:
        """
        Subclasses must implement this method, from the response, it parses it and returns a dictionary with variables
        and their respective values. All variables set in self.required_vars must be set in this method, or parse()
        will raise a FuzzowskiRuntimeError
        Args:
            data: The response bytes

        Returns: A dictionary with all required variables (and optionally others)
        """
        pass

    def _parse_request(self, data: bytes, vars_set=Mapping[str, bytes]) -> str:
        """
        Parse the request, and returns a comprehensive response. When this function is called, the variables have been
        already extracted in self.vars
        This method should be overriden to return more comprehensive responses
        Args:
            data: The response bytes
            vars_set: The set variables (is the same as

        Returns: A string with the parsed variables
        """
        return pprint.pformat(vars_set)

    def parse(self, data: bytes):
        """
        Parse the response data bytes, sets the variables extracted, and
        Args:
            data: The response bytes

        Returns: The parsed response
        Raises FuzzowskiRuntimeException if not all required_variables are set
        """
        self.vars = self._extract_variables(data)
        self._check_vars(self.vars)
        self._set_vars(self.vars)
        return self._parse_request(data, self.vars)

    def _check_vars(self, vars_set: Mapping[str, bytes]):
        """
        Checks that all required vars were set by the last time _extract_variables() was called
        Raises FuzzowskiRuntimeError if a required_var was not set by _extract_variables()
        """
        for var in self.required_vars:
            if vars_set is None or var not in vars_set or vars_set[var] is None:
                self._empty_vars()
                raise FuzzowskiRuntimeError(f'The variable {var} was not set')

    def _set_vars(self, vars_set: Mapping[str, bytes]):
        """
        Set the variables passed as argument in the global mutants.blocks.VARIABLES
        Args:data
            vars_set: The variables
        """
        blocks.VARIABLES.update(vars_set)

    def _empty_vars(self):
        """
        Set all vars of this Response to None
        """
        for var in self.required_vars + self.optional_vars:
            blocks.VARIABLES[var] = None


