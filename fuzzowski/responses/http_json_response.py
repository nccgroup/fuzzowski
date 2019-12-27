from io import BytesIO
from typing import List, Mapping
from http.client import HTTPResponse
from .response import Response
import json
from fuzzowski.exception import FuzzowskiRuntimeError


class HTTPJsonResponse(Response):
    """The Response object contains methods to parse the request, set the variables found and print the response"""
    def __init__(self, name: str, required_vars: List[str], optional_vars: List[str]):
        super().__init__(name, required_vars, optional_vars)

    def _extract_variables(self, data: bytes) -> Mapping[str, bytes]:
        """
        Subclasses must implement this method, from the response, it parses it and returns a dictionary with variables
        and their respective values. All variables set in self.required_vars must be set in this method, or parse()
        will raise a FuzzowskiRuntimeError
        Args:
            data: The response bytes

        Returns: A dictionary with all required variables (and optionally others)
        """
        response_vars = {}
        try:
            source = FakeSocket(data)
            response = HTTPResponse(source)
            response.begin()
            content_length = int(response.getheader('Content-Length'))
            body = response.read(content_length)
            json_body = json.loads(body)
            for var in self.required_vars + self.optional_vars:
                if var in json_body:
                    response_vars[var] = bytes(json_body[var], encoding='utf-8')
        except json.decoder.JSONDecodeError:
            pass
        except Exception:
            raise
        return response_vars


# Just to use HTTPResponse
class FakeSocket():
    def __init__(self, response_bytes):
        self._file = BytesIO(response_bytes)

    def makefile(self, *args, **kwargs):
        return self._file

