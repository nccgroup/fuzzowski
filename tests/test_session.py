from fuzzowski.mutants.spike import *
from fuzzowski.session import Session
import pytest
import os

@pytest.fixture
def test_session():
    s_initialize('r1')
    with s_block('b0'):
        with s_block('b1'):
            s_string(b'str1', name='str1')
            s_static(b' ')
        s_checksum('b1', algorithm='md5', output_format='hex', name='md5_b1')
        s_delim(b':')
    s_byte(b'\xff')
    s_static(b'.')
    s_variable('var1', b'NOTSET')
    s_repeat('b0', min_reps=0, max_reps=2)

    s_initialize('r1b')
    s_string('test', name='r1bstring')

    s_initialize('r2')
    s_initialize('r2b')

    s = Session()
    return s


def test_graph(test_session):
    s = test_session
    s.connect(s_get('r1'))
    s.connect(s_get('r1'), s_get('r1b'))

    s.connect(s_get('r2'))
    s.connect(s_get('r2'), s_get('r2b'))

    assert s.num_mutations == s_get('r1').num_mutations + s_get('r1b').num_mutations \
           + s_get('r2').num_mutations + s_get('r2b').num_mutations


def test_session_movements():
    # b'AW'
    s_initialize('request1')
    s_mutant(b'A', name='mutant11', mutations=[b'B', b'C', b'D'])
    s_mutant(b'W', name='mutant12', mutations=[b'X', b'Y', b'Z'])

    # b'A :3.W'
    s_initialize('request2')
    with s_block('b0'):
        with s_block('b1'):
            s_mutant(b'A', name='mutant21', mutations=[b'B', b'C', b'D'])
            s_static(b' ')
        s_delim(b':', fuzzable=False)
    s_size('b0', inclusive=False, output_format='ascii', fuzzable=False)
    s_static(b'.')
    s_mutant(b'W', name='mutant22', mutations=[b'X', b'Y', b'Z'])

    session = Session()
    session.connect(s_get('request1'))
    session.connect(s_get('request1'), s_get('request2'))

    r1 = s_get('request1')
    r2 = s_get('request2')

    # Check number of mutations
    assert session.num_mutations == r1.num_mutations + r2.num_mutations == 12

    assert session.test_case is None
    assert session.mutant_index == 0

    test_case = session.goto(0) # goto(0) == goto(1)
    assert test_case is not None and test_case == session.test_case

    assert test_case.id == 1
    assert test_case.request == r1
    assert test_case.request.mutant.name == 'mutant11'
    assert len(test_case.path) == 2
    assert test_case.path[0].dst == r1

    test_case = session.goto(6)
    assert test_case.id == 6
    assert test_case.request.mutant_index == 6
    assert test_case.request == r1
    assert test_case.request.mutant.name == 'mutant12'

    test_case = session.next()
    assert test_case.id == 7
    assert test_case.request.mutant_index == 1 # It is the first test case of request2
    assert test_case.request == r2
    assert test_case.request.mutant.name == 'mutant21'
    assert r1.mutant_index == 0  # R1 should have been reset

    test_case = session.goto(1)
    assert test_case is not None and test_case == session.test_case
    assert test_case.id == 1
    assert test_case.request == r1
    assert test_case.request.mutant.name == 'mutant11'
    assert len(test_case.path) == 2
    assert test_case.path[0].dst == r1

    test_case = session.goto(session.num_mutations) # Last mutation
    assert test_case.id == session.num_mutations == 12
    assert test_case.request.mutant_index == 6  # It is the first test case of request2
    assert test_case.request == r2
    assert test_case.request.mutant.name == 'mutant22'
    assert r1.mutant_index == 0

    test_case = session.goto("request1.mutant12")
    assert test_case.id == 4
    test_case = session.goto(r2.name)
    assert test_case.request == r2
    assert test_case.id == 7
    assert test_case.request.mutant.name == 'mutant21'
    session.skip()
    assert test_case.request.mutant.name == 'mutant22'


    session.disable_by_path_name("request1.mutant11")
    assert "request1.mutant11" in session.disabled_elements
    session.disable_by_path_name("request1.mutant11", disable=False)  # Enable
    assert "request1.mutant11" not in session.disabled_elements
    session.disable_by_path_name("request1.mutant12", disable=False)
    assert "request1.mutant12" not in session.disabled_elements

    with pytest.raises(FuzzowskiRuntimeError):
        session.disable_by_path_name("notexist")
    with pytest.raises(FuzzowskiRuntimeError):
        session.disable_by_path_name("request1.notexist")
    with pytest.raises(FuzzowskiRuntimeError):
        session.disable_by_path_name("mutant11")
    with pytest.raises(FuzzowskiRuntimeError):
        session.disable_by_path_name("sad.dasd.dasd")

    test_case = session.goto(6)
    session.add_suspect(test_case)
    session.add_suspect(test_case)
    assert len(session.suspects) == 1
    assert session.suspects[6] == test_case


