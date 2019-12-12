import pytest
import os

from fuzzowski import FuzzowskiRuntimeError
from fuzzowski.mutants.primitives.random_data import RandomData


@pytest.fixture
def test_random():
    """Returns a String('Test')"""
    return RandomData(b'Test', name='random1', min_length=4, max_length=4, max_mutations=5)


def test_random_init(test_random):
    assert next(test_random) != b'Test'
    assert test_random.num_mutations == 5


def test_random1(test_random):
    assert test_random.render() == b'Test'

    assert len(next(test_random)) == 4


def test_random_original_value(test_random):
    test_random.goto(3)
    assert test_random.original_value == b'Test'


def test_random_reset(test_random):
    for x in test_random:
        pass
    assert test_random.render() == test_random.original_value == b'Test'

