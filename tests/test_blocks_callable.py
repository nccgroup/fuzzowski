import pytest

from fuzzowski.mutants.blocks.request import Request
from fuzzowski.mutants.blocks import Callable
from fuzzowski.mutants.spike import *
from fuzzowski import blocks


def mock_generate_scramble_key(client_sign_key: bytes, username: bytes) -> bytes:
    """ Mock function to test Callable """
    salt = username
    server_sign_key = b'\x00' * 4
    sign_key = client_sign_key + server_sign_key

    scramble_key = sign_key + salt
    return scramble_key


@pytest.fixture
def test_callable():
    request = Request('request_test_callable')
    callable = Callable(request=request, value=b'\x00' * 8, function=mock_generate_scramble_key,
                        var_args=['client_sign_key', 'username'],
                        fuzzable=True, name='test_callable')
    return callable


def test_callable1(test_callable):

    # We have not set the client_sign_key and username variables, so the mock_generate_scramble_key will raise an error
    with pytest.raises(TypeError):
        assert test_callable.render()

    # We set the variables
    blocks.VARIABLES['username'] = b'MOCKUSER'
    blocks.VARIABLES['client_sign_key'] = b'\xAA'*4

    assert (test_callable.render() == mock_generate_scramble_key(client_sign_key=b'\xAA'*4, username=b'MOCKUSER')
            == b'\xAA' * 4 + b'\x00' * 4 + b'MOCKUSER')


def test_callable_original_value(test_callable):
    assert test_callable.original_value == b'\x00' * 8


def test_callable_spike():
    s_initialize('request_callable_test1')
    s_callable(b'\x00' * 8, function=mock_generate_scramble_key, var_args=['client_sign_key', 'username'],
               name='scramble_key')

    request = s_get('request_callable_test1')
    request.variables['username'] = b'MOCKUSER'
    request.variables['client_sign_key'] = b'\xAA' * 4

    assert request.render() == b'\xAA' * 4 + b'\x00' * 4 + b'MOCKUSER'

    s_initialize('request_callable_test2')
    s_callable(b'\x00' * 8, function=mock_generate_scramble_key, name='scramble_key',
               var_args=None, client_sign_key=b'\xCC', username=b'MOCKUSER2')

    request2 = s_get('request_callable_test2')
    assert request2.render() == b'\xCC' + b'\x00' * 4 + b'MOCKUSER2'
