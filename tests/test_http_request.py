import pytest
from fuzzowski import *
# Standard library imports...

from http.server import BaseHTTPRequestHandler, HTTPServer
import socket
from threading import Thread

from fuzzowski.monitors import IMonitor

stop = False

id = 1
class MockServerRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # Process an HTTP GET request and return a response with an HTTP 200 status.
        self._handle_test()
        return

    def _handle_test(self):
        # self.send_response(200)
        # self.send_header("Request-id", f"{self.i}")
        # self.end_headers()
        if len(self.path) > 1000:  # Mock a failure when path > 1000
            # self.send_error(500, 'THE PATH')
            print('Mocking error, stopping HTTP Server')
            mock_server.shutdown()
        else:
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length)
            print(body)
            if body.startswith(b'op='):  # lets check the op value
                if len(body[3:]) > 4000: # If it has more than 4K chars, send error message
                    print('Mocking error 2, Sending error 500')
                    self.send_error(500, 'ERROR 500')
                    return

            self.send_response(200)
            global id
            self.send_header("Request-id", f"{id}")
            self.end_headers()

            id += 1


class MockHTTPServer(HTTPServer):
    """http server that reacts to self.stop flag"""

    def serve_forever(self, poll_interval=0.5):
        """Handle one request at a time until stopped."""
        self.stop = False
        while not self.stop:
            self.handle_request()

    def shutdown(self):
        # print("SERVER STOPPED")
        self.stop = True
        self.socket.close()


mock_server = None


def mock_http_server():
    global mock_server
    mock_server = MockHTTPServer(('localhost', 31337), MockServerRequestHandler)
    # Start running mock server in a separate thread.
    # Daemon threads automatically shut down when the main process exits.
    mock_server_thread = Thread(target=mock_server.serve_forever)
    # mock_server_thread = Thread(target=request_handler)
    mock_server_thread.setDaemon(True)
    mock_server_thread.start()


class MockHTTPTestMonitor(IMonitor):
    @staticmethod
    def name() -> str:
        return "Mock_HTTP_Test_Monitor"

    @staticmethod
    def help():
        return ""

    def test(self) -> bool:
        conn = self.get_connection_copy()
        result = True
        return result


def initialize_request():
    s_initialize('http_request')
    s_string(b"POST", name='http_method')
    s_static(b" ")
    s_string(b'/', name='path')
    s_static(b" HTTP/1.1")
    s_static(b"\r\n")
    s_string(b"Host: ", name='host_header_name')
    s_string(b'127.0.0.1', name='host_header_hostname')
    s_delim(b':', name='host_port_separator')
    s_string(b'31337', name='host_header_port')
    s_static(b"\r\n")
    s_static(b"Content-Type: ", name = 'header_contenttype_name')
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
    s_static(b"Content-Length: ")
    s_size("post_body", output_format="ascii", signed=True, fuzzable=True, name='ContentLength_size')
    s_static(b"\r\n")
    # s_repeat('fuzz_header', min_reps=0, max_reps=1000, step=100)
    s_delim(b"\r\n", name='crlf_headers_body')

    # body
    with s_block('post_body'):
        s_string(b'op', name='param_op_name')
        s_delim(b'=', name='param_op_delim')
        s_string(b'fuzz', name='param_op_value')

    s_response(RegexResponse, name='id_response', required_vars=['id'], optional_vars=[],
               regex_list=[b'Request-id: (?P<id>[0-9]+)'])


def test_http_request():
    initialize_request()
    mock_http_server()

    target = Target(connection=SocketConnection('127.0.0.1',
                                                31337,
                                                proto='tcp',
                                                bind=None,
                                                send_timeout=5.0,
                                                recv_timeout=5.0
                                                )
                    )
    session = Session(target=target)
    session.connect(s_get('http_request'))

    session.next()
    assert session.mutant_index == 1
    # session.test_case.print_requests()
    session.test()
    assert session.test_case.request.variables['id'] == b'1'
    session.run_next()
    assert session.mutant_index == 2

    # Lets do some tests in the path, where the server will stop if a path > 1000 characters is received
    session.goto('http_request.path')
    assert session.test_case.request.mutant.name == 'path'

    for i in range(10):
        # print('TC', session.test_case.id)
        session.run_next()
        # print('TC', session.test_case.id)
        if len(session.suspects) > 0:
            break

    assert [tc for tc in session.suspects.values()][0].request.mutant.name == 'path'

    print('Restart MOCK server')
    # Next test, will test the monitor
    mock_http_server()
    #
    session.goto('http_request.param_op_value')
    assert session.test_case.request.mutant.name == 'param_op_value'
    print(f'TC: {session.test_case.id}')
    session.run_next()
    for i in range(10):
        # print('TC', session.test_case.id)
        session.run_next()
        # print('TC', session.test_case.id)
        if len(session.suspects) > 1:
            break
    print(session.suspects)



