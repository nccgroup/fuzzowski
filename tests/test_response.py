from fuzzowski import *
import pytest
import re

def test_response():

    s_initialize('testreq1')
    s_mutant(b'A', name='mutant21', mutations=[b'B', b'C', b'D'])
    s_mutant(b'W', name='mutant22', mutations=[b'X', b'Y', b'Z'])

    s_response(RegexResponse, name='response_test', required_vars=['idc'], optional_vars=['path'],
               regex_list=[b'idc=(?P<idc>[a-zA-Z0-9]+)', b'path=(?P<path>[a-zA-Z0-9/_]+)'])

    request = s_get('testreq1')
    assert len(request.responses) == 1

    assert 'idc' not in request.variables

    response = request.responses[0]
    assert response.name == 'response_test'
    r_str = response.parse(b'idc=01&path=/asd')
    assert request.variables['idc'] == b'01'
    assert request.variables['path'] == b'/asd'

    r_str = response.parse(b'test=1&idc=02&test2=2')
    assert request.variables['idc'] == b'02'
    assert request.variables['path'] is None

    with pytest.raises(FuzzowskiRuntimeError):  # idc is required var
        r_str = response.parse(b'path=/')

    s_response(RegexResponse, name='response_error', required_vars=['error'], optional_vars=[],
               regex_list=[b'error=(?P<error>[a-zA-Z0-9]*)'],
               regex_args=[re.I])  # Ignore case

    response_ignorecase = request.responses[1]
    r_str = response_ignorecase.parse(b'test=1&eRROr=ignorecase&test2=2')
    assert request.variables['error'] == b'ignorecase'

    for response in request.responses:
        try:
            response.parse(b'error=')
            break
        except FuzzowskiRuntimeError:
            assert response.name == 'response_test'
    assert request.variables['error'] == b''
    assert request.variables['idc'] is None
    assert request.variables['path'] is None

    with pytest.raises(FuzzowskiRuntimeError):
        s_response(RegexResponse, name='wrong_declared_response', required_vars=['notexist'], optional_vars=[],
                   regex_list=[b'error=(?P<error>[a-zA-Z0-9]*)'])

    with pytest.raises(FuzzowskiRuntimeError):
        s_response(RegexResponse, name='wrong_declared_response', required_vars=[], optional_vars=['notexist'],
                   regex_list=[b'error=(?P<error>[a-zA-Z0-9]*)'])

    with pytest.raises(FuzzowskiRuntimeError):
        s_response(RegexResponse, name='wrong_declared_response', required_vars=['error'], optional_vars=[],
                   regex_list=[b'error=(?P<error>[a-zA-Z0-9]*)', b'notdeclared=(?P<notdeclared>[a-zA-Z0-9]*)'])
