import pytest
import os

from fuzzowski import FuzzowskiRuntimeError
from fuzzowski.mutants.primitives.string import String
from fuzzowski.mutants.primitives.static import Static
from fuzzowski.mutants.blocks.block import Block
from fuzzowski.mutants.blocks.request import Request
from fuzzowski.mutants.blocks.repeat import Repeat
from fuzzowski.mutants.spike import *


@pytest.fixture
def test_request(tmpdir):
    mutations = (
        '1\n'
        '2\n'
        '3\n'
    )
    tmpfile = os.path.join(tmpdir, 'string_mutations.txt')
    with open(tmpfile, 'w') as f:
        f.write(mutations)

    request = Request('request1')
    string1 = String('x', name='string1', filename=tmpfile, mutation_types=('file',))
    static1 = Static(b' ', name='space')

    block1 = Block('test_block', request)
    block1.push(string1)
    block1.push(static1)

    request.push(block1)
    request.pop()   # Close last block
    repeat = Repeat('test_block', request, name='test_repeat', max_reps=10, step=1)
    request.push(repeat)
    return request


def test_repeat1(test_request):
    assert test_request.render() == b'x '
    assert test_request.num_mutations == 3+11


def test_repeat_original_value(test_request):
    test_request.goto(3)
    assert test_request.original_value == b'x '


def test_repeat_mutations(test_request):
    gen = test_request.mutation_generator()
    assert next(gen) == b'1 ' == test_request.render()
    assert test_request.request.mutant.name == 'string1'
    assert next(gen) == b'2 ' == test_request.render()
    assert test_request.request.mutant.name == 'string1'
    assert next(gen) == b'3 ' == test_request.render()
    assert test_request.request.mutant.name == 'string1'

    assert next(gen) == b'x ' == test_request.render()
    assert test_request.request.mutant.name == 'test_repeat'
    assert next(gen) == b'x ' * 2 == test_request.render()
    assert test_request.request.mutant.name == 'test_repeat'
    assert next(gen) == b'x ' * 3 == test_request.render()
    assert test_request.request.mutant.name == 'test_repeat'


def test_repeat_spike():
    s_initialize('request_repeat_test')
    with s_block('block1'):
        s_static(b'x')
        s_static(b' ')
    s_repeat('block1', min_reps=0, max_reps=5)

    request = s_get('request_repeat_test')
    for i in range(0, 6):
        # block1 value + (block1 * repetitions)
        assert next(request) == b'x ' + b'x ' * i == request.render()

    request.goto(4)
    assert next(request) == b'x ' * 5 == request.render()


def test_repeat_variable_spike():
    """ Test repeat with a variable instead of repeat values """
    s_initialize('request_repeat_var_test')

    s_dword(5, output_format='ascii', name='num_repeats', mutations=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
    with s_block('block1'):
        s_static(b'x')
    s_repeat('block1', variable_name='num_repeats')

    request = s_get('request_repeat_var_test')
    dword = request.names['num_repeats']  # dword._value contains number of repetitions
    assert request.render() == dword.render() + b'x' + b'x' * dword._value

    for next_mutation in request:
        assert next_mutation == dword.render() + b'x' + b'x' * dword._value == request.render()

    request.goto(10)
    assert next(request) == dword.render() + b'x' * 11 == request.render() # 10 + 1


def test_repeat_variable_include_spike():
    """ Test repeat with a variable instead of repeat values and include = True"""
    s_initialize('request_repeat_var_include_test')
    s_dword(5, output_format='ascii', name='num_repeats', mutations=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
    with s_block('block1'):
        s_static(b'x')
    s_repeat('block1', variable_name='num_repeats', include=True)

    request = s_get('request_repeat_var_include_test')
    dword = request.names['num_repeats']  # dword._value contains number of repetitions
    assert request.render() == dword.render() + b'x' * max(dword._value, 1)

    for next_mutation in request:
        assert next_mutation == dword.render() + b'x' * max(dword._value, 1) == request.render()

    request.goto(7)
    assert next(request) == dword.render() + b'x' * 7 == request.render()
