import pytest
from fuzzowski import *
from .mock_http_server.mock_http_server import mock_http_server
from .mock_http_server.mock_http_fuzzer import MockHTTPFuzzer
from .mock_http_server.mock_http_monitor import MockHTTPTestMonitor


def test_http_request():
    mock_http_server()

    target = Target(connection=SocketConnection('127.0.0.1',
                                                31337,
                                                proto='tcp',
                                                bind=None,
                                                send_timeout=5.0,
                                                recv_timeout=5.0
                                                )
                    )
    session = Session(target=target, new_connection_between_requests=True)

    # Initialize requests from the Mock HTTP Fuzzer (this is what is done in __main__ when selecting a Fuzzer)
    fuzzer = MockHTTPFuzzer
    fuzzer.define_nodes()
    fuzz_methods = [method for method in fuzzer.get_requests()]
    for method in fuzz_methods:
        method(session)  # Initialize the request with this

    session.next()
    assert session.mutant_index == 1
    # session.test_case.print_requests()
    session.test()
    # assert session.test_case.request.variables['id'] is None
    session.run_next()
    assert session.mutant_index == 2

    # Lets do some tests in the path, where the server will stop if a path > 1000 characters is received
    session.goto('http_headers.path')
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
    session.goto('post_op.param_op_value')
    assert session.test_case.request.mutant.name == 'param_op_value'
    print(f'TC: {session.test_case.id}')

    session.test()
    assert session.test_case.request.variables['id'] == b'1'
    assert session.test_case.request.variables['token'] is not None
    assert len(session.disabled_elements) == 0

    for i in range(10):
        # print('TC', session.test_case.id)
        session.run_next()
        # print('TC', session.test_case.id)
        if len(session.suspects) > 1:
            break
    assert [tc for tc in session.suspects.values()][-1].mutant_name == 'param_op_value'
    print(session.suspects)



