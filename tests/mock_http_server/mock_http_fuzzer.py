from fuzzowski.fuzzers.ifuzzer import IFuzzer
from fuzzowski.mutants.spike import *
from fuzzowski import ITargetConnection, IFuzzLogger, Session, Request, RegexResponse, HTTPJsonResponse


class MockHTTPFuzzer(IFuzzer):

    name = 'mock_http'  # This is how the fuzzer is named in the Fuzzowski Arguments, with the -f option

    @staticmethod
    def get_requests() -> List[callable]:
        """Get possible requests, returns a list of all the callables which connects the paths to the session"""
        return [MockHTTPFuzzer.http_headers, MockHTTPFuzzer.get_token, MockHTTPFuzzer.post_op]

    @staticmethod
    def define_nodes(*args, **kwargs) -> None:
        # ================================================================#
        # HTTP HEADERS                                                    #
        # ================================================================#
        s_initialize('http_headers')
        s_string(b"GET", name='http_method')
        s_static(b" ")
        s_string(b'/', name='path')
        s_static(b" HTTP/1.1")
        s_static(b"\r\n")
        s_string(b"Host: ", name='host_header_name')
        s_string(b'127.0.0.1', name='host_header_hostname')
        s_delim(b':', name='host_port_separator')
        s_string(b'31337', name='host_header_port')
        s_static(b"\r\n")
        s_static(b"Content-Type: ", name='header_contenttype_name')
        s_string(b"application/x-www-form-urlencoded", name='header_contenttype_value')
        s_static(b"\r\n")
        s_static(b"Connection: close\r\n")
        s_static(b"User-Agent: ")
        s_string(b"Fuzzowski Agent", name='user_agent')
        s_static(b"\r\n")
        with s_block('fuzz_header'):
            s_string(b'Fuzz-Header', name='header_name')
            s_delim(b':', name='header_separator')
            s_delim(b' ', name='header_separator_space')
            s_string(b"Fuzzowski", name='header_value')
            s_delim(b"\r\n", name='header_crlf')
        s_static(b"\r\n")
        # s_repeat('fuzz_header', min_reps=0, max_reps=1000, step=100)
        s_delim(b"\r\n", name='crlf_headers_body')

        # ================================================================#
        # GET_TOKEN                                                       #
        # ================================================================#
        s_initialize('get_token')
        s_static(b'GET /token HTTP/1.1\r\n'
                 b'Host: 127.0.0.1: 31337\r\n')
        s_string(b'User', name='user_header_name')
        s_delim(b':', name='user_header_separator', fuzzable=False)
        s_static(b' ')
        s_string(b'Mario', name='user_header_value')
        s_static(b'\r\n\r\n', name='http_request_end')

        # This response takes the JSON parameter "token" of the response and set a variable with it
        s_response(HTTPJsonResponse, name='token_response', required_vars=['token'], optional_vars=[])

        # ================================================================#
        # POST OP REQUEST                                                 #
        # ================================================================#
        s_initialize('post_op')
        s_static(b'POST /op HTTP/1.1\r\n'
                 b'Host: 127.0.0.1: 31337\r\n'
                 b'Content-Type: application/x-www-form-urlencoded\r\n'
                 b'Connection: close\r\n'
                 )
        s_static(b'Token: ')
        s_variable('token', value=b'NOTSET')  # Takes the Variable 'token' set by the response of the /token request
        s_static(b"\r\nContent-Length: ")
        s_size("post_body", output_format="ascii", signed=True, fuzzable=True, name='ContentLength_size')
        s_static(b'\r\n\r\n')
        # body
        with s_block('post_body'):
            s_string(b'op', name='param_op_name')
            s_delim(b'=', name='param_op_delim')
            s_string(b'fuzz', name='param_op_value')

        s_response(RegexResponse, name='id_response', required_vars=['id'], optional_vars=[],
                   regex_list=[b'Request-id: (?P<id>[0-9]+)'])

    # ================================================================#
    # Callable methods to connect our requests to the session         #
    # ================================================================#

    @staticmethod
    def http_headers(session: Session) -> None:
        session.connect(s_get('http_headers'))

    @staticmethod
    def get_token(session: Session) -> None:
        session.connect(s_get('get_token'))

    @staticmethod
    def post_op(session: Session) -> None:
        session.connect(s_get('get_token'), s_get('post_op'))



