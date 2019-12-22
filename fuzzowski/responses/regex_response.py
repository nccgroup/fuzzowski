from typing import List, Mapping
from .response import Response
import re
from fuzzowski.exception import FuzzowskiRuntimeError


class RegexResponse(Response):
    """The Response object contains methods to parse the request, set the variables found and print the response"""
    def __init__(self, name: str, required_vars: List[str], optional_vars: List[str], regex_list: List[bytes],
                 regex_args: List = ()):
        super().__init__(name, required_vars, optional_vars)
        assert len(regex_list) > 0
        self.regex_list = []
        regex_keys = []
        for regex in regex_list:
            assert type(regex) is bytes
            compiled_regex = re.compile(regex, *regex_args)
            self.regex_list.append(compiled_regex)
            regex_keys.extend(compiled_regex.groupindex.keys())
        if len(set(regex_keys).difference(self.required_vars + self.optional_vars)) != 0:
            raise FuzzowskiRuntimeError("There are differences between the variables of the regex list and the declared"
                                        "optional and required vars. It must coincide!")

    def _extract_variables(self, data: bytes) -> Mapping[str, bytes]:
        """
        Subclasses must implement this method, from the response, it parses it and returns a dictionary with variables
        and their respective values. All variables set in self.required_vars must be set in this method, or parse()
        will raise a FuzzowskiRuntimeError
        Args:
            data: The response bytes

        Returns: A dictionary with all required variables (and optionally others)
        """
        var_dict = {}
        for regex in self.regex_list:
            m = regex.search(data)
            for key in regex.groupindex.keys():
                if m is not None and key in m.groupdict():
                    var_dict[key] = m.groupdict()[key]
                else:
                    var_dict[key] = None
        return var_dict
