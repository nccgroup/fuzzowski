import pytest
import os
import hashlib
from fuzzowski.mutants.spike import *
import pytest


def test_md5_values():
    s_initialize('request_checksum_test')
    with s_block('block1'):
        s_string(b'hola', name='str1')
        s_static(b' ')
    s_checksum('block1', algorithm='md5', name='md5_b1')
    s_static(b'   ')
    with s_block('block2'):
        s_string(b'recursive', fuzzable=False, name='str2')
        s_checksum('block2', algorithm='md5', name='md5_b2')
    request = s_get('request_checksum_test')
    md5_b1 = request.names['md5_b1']
    assert md5_b1.render().hex() == '51db41a195b9a4b26f9e1f16d72e7b20'  # md5('hola ')
    next(request)
    assert md5_b1.render().hex() == '2e6c5ce94092972ad11a44cfa7e4812c'  # md5('holahola ')

    md5_b2 = request.names['md5_b2']
    assert md5_b2.render().hex() == hashlib.md5(b'recursive' + b'\x00'*16).digest().hex()


def test_checksum_reset():
    s_initialize('request_checksum_test2')
    with s_block('block1'):
        s_string(b'hola', name='str1')
        s_static(b' ')
    s_checksum('block1', algorithm='md5', name='md5_b1')
    s_static(b'   ')
    with s_block('block2'):
        s_string(b'recursive', fuzzable=False, name='str2')
        s_checksum('block2', algorithm='md5', name='md5_b2')
    request = s_get('request_checksum_test2')
    assert request.mutant is None
    md5_b1 = request.names['md5_b1']
    mutation1 = next(md5_b1)
    next(md5_b1)
    next(md5_b1)
    assert md5_b1.mutant_index == 3
    md5_b1.reset()
    assert md5_b1.mutant_index == 0
    assert next(md5_b1) == mutation1
    assert md5_b1.mutant_index == 1
    md5_b1.goto(0)
    assert md5_b1.mutant_index == 0
    assert next(md5_b1) == mutation1
    assert md5_b1.mutant_index == 1



# TODO: Only tested md5, should test others!
