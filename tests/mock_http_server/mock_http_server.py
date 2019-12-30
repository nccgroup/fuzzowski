"""
This implements a mock http server that will simulate different failures in different parts, to test the session with
a fuzzer module. This code is just for tests, so it is probably dirty and baaaad
"""
import uuid
from threading import Thread
import json

from http.server import BaseHTTPRequestHandler, HTTPServer

mock_server = None
stop = False
id = 1

class MockServerRequestHandler(BaseHTTPRequestHandler):
    tokens = []  # List of saved tokens

    def do_GET(self):
        if len(self.path) > 1000:                               # 1. Mock a failure when path > 1000
            # self.send_error(500, 'THE PATH')
            print('Mocking error, stopping HTTP Server')
            mock_server.shutdown()
        elif self.path == '/token':
            # Gen token and save it
            token = str(uuid.uuid1())
            self.tokens.append(token)

            json_str = json.dumps({'token': token})
            print(json_str)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', len(json_str))
            self.end_headers()
            self.wfile.write(json_str.encode(encoding='utf_8'))
            return
        else:
            self.send_error(404)
            self.end_headers()

    def do_POST(self):
        # self.send_response(200)
        # self.send_header("Request-id", f"{self.i}")
        # self.end_headers()
        if len(self.path) > 1000:                               # 1. Mock a failure when path > 1000
            # self.send_error(500, 'THE PATH')
            print('Mocking error, stopping HTTP Server')
            mock_server.shutdown()

        else:
            token = self.headers.get('Token')                   # 2. For POST we want to first "authenticate" a token
            if token not in self.tokens:
                self.send_error(403, 'Invalid Token')
                return
            self.tokens.remove(token)  # Delete 1 time token from list

            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length)
            print(body)
            if body.startswith(b'op='):  # lets check the op value
                if len(body[3:]) > 2000:                        # 3. If it has more than 2K chars, send error message,
                                                                #  then shutdown the server (simulating a crash)
                    print('Mocking error 2, Sending error 500')
                    self.send_error(500, 'ERROR 500')
                    mock_server.shutdown()
                    return

            global id
            self.send_response(200)
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


def mock_http_server():
    global mock_server
    mock_server = MockHTTPServer(('localhost', 31337), MockServerRequestHandler)
    # Start running mock server in a separate thread.
    # Daemon threads automatically shut down when the main process exits.
    mock_server_thread = Thread(target=mock_server.serve_forever)
    # mock_server_thread = Thread(target=request_handler)
    mock_server_thread.setDaemon(True)
    mock_server_thread.start()
    return mock_server_thread


def main():
    mock_server_thread = mock_http_server()
    mock_server_thread.join()


if __name__ == '__main__':
    main()
