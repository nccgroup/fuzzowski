from fuzzowski import constants
from fuzzowski.mutants.spike import *
import hashlib
import pytest


def test_request_spike():
    s_initialize('request_test_complex')
    with s_block('b0'):
        with s_block('b1'):
            s_string(b'str1', name='str1')
            s_static(b' ')
        s_checksum('b1', algorithm='md5', output_format='hex', name='md5_b1')
        s_delim(b':')
    s_size('b0', inclusive=True, output_format='binary', length=4, endian=constants.BIG_ENDIAN)
    s_byte(b'\xff')
    s_static(b'.')
    s_variable('var1', b'NOTSET')
    s_repeat('b0', min_reps=0, max_reps=2)

    request = s_get('request_test_complex')

    b1_rendered = (b'str1 '
                   + hashlib.md5(b'str1 ').digest().hex().encode('utf-8')
                   + b':')
    assert request.render() == (b1_rendered
                                + b'\x00\x00\x00\x2a'
                                + b'\xff'
                                + b'.'
                                + b'NOTSET')

    request.goto(request.num_mutations) # last mutation

    assert request.render() == (b1_rendered
                                + b'\x00\x00\x00\x2a'
                                + b'\xff'
                                + b'.'
                                + b'NOTSET'
                                + b1_rendered * 2)

    request.reset()
    request.variables['var1'] = b'SET!!!'
    assert request.render() == (b1_rendered
                                + b'\x00\x00\x00\x2a'
                                + b'\xff'
                                + b'.'
                                + b'SET!!!')


def test_request_reset():
    s_initialize('request_test_simple')
    s_mutant(b'A', name='mutant21', mutations=[b'B', b'C', b'D'])
    s_mutant(b'W', name='mutant22', mutations=[b'X', b'Y', b'Z'])
    test_request = s_get('request_test_simple')
    assert test_request.render() == b'AW'
    assert test_request.mutant_index == 0
    assert next(test_request) == b'BW' == test_request.render()
    assert test_request.mutant_index == 1
    assert next(test_request) == b'CW' == test_request.render()
    assert test_request.mutant_index == 2
    assert test_request.mutant.name == 'mutant21'
    assert next(test_request) == b'DW' == test_request.render()
    assert test_request.mutant_index == 3
    assert test_request.mutant.name == 'mutant21'
    assert next(test_request) == b'AX' == test_request.render()
    assert test_request.mutant_index == 4
    assert test_request.mutant.name == 'mutant22'
    assert next(test_request) == b'AY' == test_request.render()
    assert test_request.mutant_index == 5
    assert next(test_request) == b'AZ' == test_request.render()
    assert test_request.mutant_index == 6
    assert test_request.mutant.name == 'mutant22'
    with pytest.raises(StopIteration):
        next(test_request)
    assert test_request.mutant_index == 0
    assert test_request.render() == b'AW'
    assert test_request.mutant is None

    assert next(test_request) == b'BW' == test_request.render()
    assert test_request.mutant_index == 1
    assert test_request.mutant.name == 'mutant21'

    test_request.reset()
    assert test_request.mutant_index == 0
    assert test_request.render() == b'AW'
    assert test_request.mutant is None

    assert next(test_request) == b'BW' == test_request.render()
    assert test_request.mutant_index == 1
    assert test_request.mutant.name == 'mutant21'


def test_request_goto():
    s_initialize('request_test_simple2')
    s_mutant(b'A', name='mutant21', mutations=[b'B', b'C', b'D'])
    s_mutant(b'W', name='mutant22', mutations=[b'X', b'Y', b'Z'])
    test_request = s_get('request_test_simple2')
    assert test_request.render() == b'AW'
    assert test_request.mutant_index == 0
    assert next(test_request) == b'BW' == test_request.render()
    assert test_request.mutant_index == 1
    assert next(test_request) == b'CW' == test_request.render()
    assert test_request.mutant_index == 2
    assert test_request.mutant.name == 'mutant21'
    assert next(test_request) == b'DW' == test_request.render()
    assert test_request.mutant_index == 3
    assert test_request.mutant.name == 'mutant21'
    assert next(test_request) == b'AX' == test_request.render()
    assert test_request.mutant_index == 4
    assert test_request.mutant.name == 'mutant22'
    assert next(test_request) == b'AY' == test_request.render()
    assert test_request.mutant_index == 5
    assert next(test_request) == b'AZ' == test_request.render()
    assert test_request.mutant_index == 6
    assert test_request.mutant.name == 'mutant22'
    with pytest.raises(StopIteration):
        next(test_request)
    assert test_request.mutant_index == 0
    assert test_request.render() == b'AW'
    assert test_request.mutant is None

    assert next(test_request) == b'BW' == test_request.render()
    assert test_request.mutant_index == 1
    assert test_request.mutant.name == 'mutant21'

    test_request.reset()
    assert test_request.mutant_index == 0
    assert test_request.render() == b'AW'
    assert test_request.mutant is None

    assert next(test_request) == b'BW' == test_request.render()
    assert test_request.mutant_index == 1
    assert test_request.mutant.name == 'mutant21'

def test_request_movements():
    s_initialize('request_test_complex2')
    with s_block('b0'):
        with s_block('b1'):
            s_string(b'str1', name='str1')
            s_static(b' ')
        s_checksum('b1', algorithm='md5', output_format='hex', name='md5_b1')
        s_delim(b':')
    s_size('b0', inclusive=True, output_format='binary', length=4, endian=constants.BIG_ENDIAN)
    s_byte(b'\xff')
    s_static(b'.')
    s_variable('var1', b'NOTSET')
    s_repeat('b0', min_reps=0, max_reps=2)

    request = s_get('request_test_complex2')

    i=0
    for mutation in request:
        i+=1
        assert request.mutant_index == i
        assert request.mutant.mutant_index != 0
        for item in request.stack:
            if item != request.mutant:
                if not isinstance(item, blocks.Block):
                    assert item.mutant_index == 0
            else:
                assert item.mutant_index != 0

    for item in request.stack:
        assert item.mutant_index == 0