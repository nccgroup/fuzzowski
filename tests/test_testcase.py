from fuzzowski import constants, Target, SocketConnection
from fuzzowski.graph import Graph
from fuzzowski.mutants.spike import *
import hashlib
import pytest

from fuzzowski.session import Session
from fuzzowski.testcase import TestCase


@pytest.mark.filterwarnings("ignore:PytestCollectionWarning")
def test_testcase1():

    # b'A :3.W'
    s_initialize('testcaserequest1')
    with s_block('b0'):
        with s_block('b1'):
            s_mutant(b'A', name='mutant11', mutations=[b'B', b'C', b'D'])
            s_static(b' ')
        s_delim(b':', fuzzable=False)
    s_size('b0', inclusive=False, output_format='ascii', fuzzable=False)
    s_static(b'.')
    s_mutant(b'W', name='mutant12', mutations=[b'X', b'Y', b'Z'])

    # b'AW'
    s_initialize('testcaserequest2')
    s_mutant(b'A', name='mutant21', mutations=[b'B', b'C', b'D'])
    s_mutant(b'W', name='mutant22', mutations=[b'X', b'Y', b'Z'])

    i = 0
    target = Target(connection=SocketConnection('127.0.0.1',
                             1337,
                             proto='tcp',
                             bind=31337,
                             send_timeout=5.0,
                             recv_timeout=5.0
                             ))
    session = Session(target=target)
    session.connect(s_get('testcaserequest1'))
    session.connect(s_get('testcaserequest1'), s_get('testcaserequest2'))
    path = next(session.graph.path_iterator())
    print(next(s_get('testcaserequest1')))

    test = TestCase(i, session, s_get('testcaserequest1'), path)
    assert test.path_name == '[testcaserequest1]->testcaserequest2'
    assert test.name == '[testcaserequest1]->testcaserequest2.mutant11.1'

    print(next(s_get('testcaserequest1')))
    test = TestCase(i, session, s_get('testcaserequest1'), path)
    assert test.name == '[testcaserequest1]->testcaserequest2.mutant11.2'
