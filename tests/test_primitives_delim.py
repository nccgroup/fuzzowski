import pytest
from fuzzowski.mutants.primitives import Delim


@pytest.fixture
def test_delim():
    return Delim(b':', name='test_delim', fuzzable=True)


@pytest.fixture
def test_delim_nonfuzzable():
    return Delim(b':', name='test_delim', fuzzable=False)


def test_delim1(test_delim):
    assert test_delim.render() == b':'

    assert test_delim.original_value == test_delim.render()
    next_mutation = next(test_delim)
    assert test_delim.original_value != next_mutation
    assert next_mutation == test_delim.render()

    all_mutations = [x for x in test_delim]
    assert len(test_delim._mutations) == len(all_mutations)

    assert b':' * 100 in all_mutations
