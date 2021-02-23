import pytest
import os

from fuzzowski import FuzzowskiRuntimeError
from fuzzowski.mutants.primitives.string import String
from fuzzowski.mutants.primitives.static import Static
from fuzzowski.mutants.blocks.block import Block
from fuzzowski.mutants.blocks.request import Request
from fuzzowski.mutants.blocks import Wrap
from fuzzowski.mutants.spike import *


@pytest.fixture
def test_wrap():

    wrap = Wrap(b'test', prefix=b'(', suffix=b')', min_reps=0, max_reps=20, step=2, name='wrap')
    return wrap


def test_wrap1(test_wrap):
    assert test_wrap.render() == b'test'
    assert test_wrap.num_mutations == 11


def test_wrap_original_value(test_wrap):
    test_wrap.goto(3)
    assert test_wrap.original_value == b'test'


def test_wrap_mutations(test_wrap):
    gen = test_wrap.mutation_generator()
    assert next(gen) == b'test' == test_wrap.render()
    assert next(gen) == b'((test))' == test_wrap.render()
    assert next(gen) == b'((((test))))' == test_wrap.render()
    assert next(gen) == b'((((((test))))))' == test_wrap.render()


def test_wrap_spike():
    s_initialize('request_wrap_test')
    s_wrap(b'test', b'[', b']', min_reps=0, max_reps=5)

    request = s_get('request_wrap_test')
    for i in range(0, 6):
        # block1 value + (block1 * repetitions)
        assert next(request) == b'['*i + b'test' + b']'*i == request.render()