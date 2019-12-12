import pytest
from fuzzowski.mutants.mutant import Mutant
from fuzzowski.exception import FuzzowskiRuntimeError

@pytest.fixture
def test_mutant():
    return Mutant(b'Test', name='test_mutant', fuzzable=True, mutations=['a', 'b', 'c'])


@pytest.fixture
def test_mutant_nonfuzzable():
    return Mutant(b'Test', name='test_mutant', fuzzable=False, mutations=['a', 'b', 'c'])


def test_mutant1(test_mutant):
    assert test_mutant.render() == b'Test'

    assert [x for x in test_mutant] == [b'a', b'b', b'c']
    assert [x for x in test_mutant.mutation_generator()] == [b'a', b'b', b'c']
    assert [x for x in test_mutant.mutation_generator(0)] == [b'a', b'b', b'c']
    assert [x for x in test_mutant.mutation_generator(1)] == [b'b', b'c']
    assert [x for x in test_mutant.mutation_generator(2)] == [b'c']
    assert [x for x in test_mutant.mutation_generator(3)] == []

    assert test_mutant.num_mutations == 3

    test_mutant.disabled = True
    assert test_mutant.num_mutations == 3

    assert next(test_mutant.mutation_generator()) == b'a'


def test_mutant_changes(test_mutant):
    """
    Test that the rendered value of the item changes when the generator next() function is called
    """
    gen = test_mutant.mutation_generator(0)
    assert test_mutant.render() == b'Test' == test_mutant.original_value
    assert test_mutant.mutant_index == 0

    actual_value = next(gen)
    assert test_mutant.render() == b'a' == actual_value
    assert test_mutant.mutant_index == 1

    actual_value = next(gen)
    assert test_mutant.render() == b'b' == actual_value
    assert test_mutant.mutant_index == 2

    gen = test_mutant.mutation_generator()  # Another generator, but without index, it will be reset
    assert test_mutant.mutant_index == 0
    actual_value = next(gen)
    assert test_mutant.render() == b'a' == actual_value
    assert test_mutant.mutant_index == 1


    gen = test_mutant.mutation_generator(0)
    assert test_mutant.render() == b'Test' == test_mutant.original_value
    assert test_mutant.mutant_index == 0
    actual_value = next(gen)
    assert test_mutant.render() == b'a' == actual_value


def test_mutant_nonfuzzable1(test_mutant_nonfuzzable):

    assert test_mutant_nonfuzzable.num_mutations == 0

    assert test_mutant_nonfuzzable.render() == b'Test'

    assert [x for x in test_mutant_nonfuzzable.mutation_generator()] == []

    with pytest.raises(FuzzowskiRuntimeError):
        assert test_mutant_nonfuzzable.mutation_generator(1)
    assert test_mutant_nonfuzzable.mutant_index == 0


def test_mutant_original_value(test_mutant):
    assert test_mutant.original_value == b'Test'

    assert test_mutant._fuzz_complete is False
    for x in test_mutant.mutation_generator():
        pass
    assert test_mutant.render() == b'Test'
    assert test_mutant.mutant_index == 0

    test_mutant.goto(test_mutant.num_mutations)
    assert test_mutant.mutant_index == test_mutant.num_mutations
    with pytest.raises(StopIteration):
        next(test_mutant)
    assert test_mutant.mutant_index == 0


def test_mutant_reset(test_mutant):
    assert next(test_mutant) == b'a'
    assert next(test_mutant) == b'b'
    assert next(test_mutant) == b'c'
    test_mutant.reset()
    assert test_mutant.mutant_index == 0
    assert next(test_mutant) == b'a'


def test_mutant_reset2(test_mutant):
    assert next(test_mutant) == b'a'
    assert next(test_mutant) == b'b'
    assert next(test_mutant) == b'c'
    test_mutant.goto(0)
    assert test_mutant.mutant_index == 0
    assert next(test_mutant) == b'a'


