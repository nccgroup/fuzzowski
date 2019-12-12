import pytest
from fuzzowski.mutants.primitives.static import Static
from fuzzowski.exception import FuzzowskiRuntimeError

@pytest.fixture
def test_static():
    """Returns a String('Test')"""
    return Static(b'Test', name='test_static')


def test_static1(test_static):
    assert test_static.render() == b'Test' == test_static.original_value

    assert len([x for x in test_static]) == 0
    assert len([x for x in test_static.mutation_generator()]) == 0

    assert test_static.num_mutations == 0

    with pytest.raises(FuzzowskiRuntimeError):
        assert test_static.mutation_generator(1), "a FuzzowskiRuntimeError exception should be raised"
