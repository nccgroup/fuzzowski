import pytest
import os

from fuzzowski import FuzzowskiRuntimeError
from fuzzowski.mutants.primitives.string import String
from fuzzowski.mutants.primitives.static import Static
from fuzzowski.mutants.blocks.block import Block
from fuzzowski.mutants.blocks.request import Request


@pytest.fixture
def test_block(tmpdir):
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
    string2 = String('y', name='string2', filename=tmpfile, mutation_types=('file',))

    block1 = Block('test_block', request)
    block1.push(string1)
    block1.push(static1)
    block1.push(string2)

    return block1


def test_block1(test_block):
    assert test_block.render() == b'x y'
    assert test_block.num_mutations == 6
    assert test_block.mutant_index == 0


def test_block_original_value(test_block):
    test_block.goto(3)
    assert test_block.original_value == b'x y'
    assert test_block.mutant_index == 3


def test_block_mutations(test_block):
    gen = test_block.mutation_generator()
    assert next(gen) == b'1 y' == test_block.render()
    assert test_block.request.mutant.name == 'string1'
    assert test_block.mutant_index == 1
    assert next(gen) == b'2 y' == test_block.render()
    assert test_block.request.mutant.name == 'string1'
    assert test_block.mutant_index == 2
    assert next(gen) == b'3 y' == test_block.render()
    assert test_block.request.mutant.name == 'string1'
    assert test_block.mutant_index == 3

    assert next(gen) == b'x 1' == test_block.render()
    assert test_block.request.mutant.name == 'string2'
    assert test_block.mutant_index == 4
    assert next(gen) == b'x 2' == test_block.render()
    assert test_block.request.mutant.name == 'string2'
    assert test_block.mutant_index == 5
    assert next(gen) == b'x 3' == test_block.render()
    assert test_block.request.mutant.name == 'string2'
    assert test_block.mutant_index == 6

    with pytest.raises(StopIteration):
        next(gen)

    assert test_block.render() == b'x y', 'The value should have been reset'
    assert test_block.request.mutant is None
    assert test_block.mutant_index == 0

    test_block.goto(0)
    assert next(test_block) == b'1 y'
    assert test_block.request.mutant.name == 'string1'
    assert test_block.mutant_index == 1

    with pytest.raises(FuzzowskiRuntimeError):
        test_block.goto(7)

    test_block.goto(0)
    for x in test_block:
        assert len(x) == 3 == len(test_block.render())
    assert test_block.render() == b'x y', 'The value should have been reset'
    assert test_block.request.mutant is None

    test_block.goto(6)
    assert test_block.render() == b'x 3'
    assert [x for x in test_block.mutation_generator(6)] == []  # Last mutation
    assert test_block.request.mutant is None
    assert test_block.mutant_index == 0


def test_block_iterator(test_block):
    assert next(test_block) == b'1 y' == test_block.render()
    assert next(test_block) == b'2 y' == test_block.render()
    assert next(test_block) == b'3 y' == test_block.render()
    assert next(test_block) == b'x 1' == test_block.render()
    assert next(test_block) == b'x 2' == test_block.render()
    assert next(test_block) == b'x 3' == test_block.render()
    assert test_block.mutant_index == 6
    with pytest.raises(StopIteration):
        next(test_block)
    assert test_block.mutant_index == 0

    test_block.goto(5)
    assert test_block.request.mutant.name == 'string2'
    assert next(test_block) == b'x 3'
    assert test_block.mutant_index == 6

    test_block.goto(6)
    assert test_block.request.mutant.name == 'string2'
    with pytest.raises(StopIteration):
        next(test_block)
    assert test_block.request.mutant is None
    assert test_block.mutant_index == 0


def test_block_reset(test_block):
    assert next(test_block) == b'1 y' == test_block.render()
    assert next(test_block) == b'2 y' == test_block.render()
    assert test_block.mutant_index == 2
    assert next(test_block) == b'3 y' == test_block.render()
    assert next(test_block) == b'x 1' == test_block.render()
    assert next(test_block) == b'x 2' == test_block.render()
    assert next(test_block) == b'x 3' == test_block.render()
    test_block.reset()
    assert test_block.mutant_index == 0
    assert next(test_block) == b'1 y' == test_block.render()
    assert test_block.mutant_index == 1


def test_block_goto(test_block):
    assert next(test_block) == b'1 y' == test_block.render()
    assert next(test_block) == b'2 y' == test_block.render()
    assert test_block.mutant_index == 2
    assert next(test_block) == b'3 y' == test_block.render()
    assert next(test_block) == b'x 1' == test_block.render()
    assert next(test_block) == b'x 2' == test_block.render()
    test_block.goto(3)
    assert test_block.mutant_index == 3
    assert next(test_block) == b'x 1' == test_block.render()
    assert next(test_block) == b'x 2' == test_block.render()
    assert next(test_block) == b'x 3' == test_block.render()
    test_block.goto(0)
    assert test_block.mutant_index == 0
    assert next(test_block) == b'1 y' == test_block.render()
    assert test_block.mutant_index == 1

    test_block.goto(1)
    assert next(test_block) == b'2 y' == test_block.render()
