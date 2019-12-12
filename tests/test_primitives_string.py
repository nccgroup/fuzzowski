import pytest
import os

from fuzzowski import FuzzowskiRuntimeError
from fuzzowski.mutants.primitives.string import String

@pytest.fixture
def test_string():
    """Returns a String('Test')"""
    return String('Test')


def test_string_init(test_string):
    assert next(test_string) != b'Test'


def test_str1(test_string):
    assert test_string.render() == b'Test'
    assert String('Test').render() == String(b'Test').render()

    assert String('Test', mutation_types='commands').num_mutations < String('Test').num_mutations


def test_string_original_value(test_string):
    test_string.goto(50)
    assert test_string.original_value == b'Test'

def test_string_reset(test_string):
    for x in test_string:
        pass
    assert test_string.render() == test_string.original_value == b'Test'

def test_string_filename(tmpdir, test_string):

    mutations = (
        'test1\n'
        'test2\n'
        'test3\n'
    )
    tmpfile = os.path.join(tmpdir, 'string_mutations.txt')
    with open(tmpfile, 'w') as f:
        f.write(mutations)

    s = String('Test', filename=tmpfile, mutation_types=('file',))
    s.goto(1)
    assert s.render() == b'test1'

    s.goto(2)
    assert s.render() == b'test2'

    assert s.num_mutations == 3, "num mutations is not 3 and the file should have 3 mutations"

    test_string.set_filename(tmpfile, replace=True)
    assert test_string.num_mutations == 3, "File mutations is not 3 and the file should have 3 mutations"

    test_string.set_callback_commands('domain.test.com', replace=True)
    mutator = test_string.mutation_generator()
    assert b'domain.test.com' in next(mutator), "The first mutation should have the callback"

    with pytest.raises(FuzzowskiRuntimeError):
        assert s.set_filename("ThisFileSureDoesNotExist23123123", replace=True), \
            "A Non-existing file should raise an exception"


def test_string_mutation_types(test_string):
    s = String('Test')
    num1 = s.num_mutations

    mutations = s.mutation_types
    mutations.pop(0)
    s.mutation_types = mutations
    assert num1 > s.num_mutations, "After popping a mutation type, the number of mutations should be lower"

    with pytest.raises(FuzzowskiRuntimeError):
        mutations += 'thisdoesnotexist'
        s.mutation_types = mutations
