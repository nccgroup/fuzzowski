import pytest
import os
from fuzzowski import String

@pytest.fixture
def test_string():
    """Returns a String('Test')"""
    return String('Test')


def test_str1(test_string):
    assert test_string.render() == b'Test'
    assert String('Test').render() == String(b'Test').render()

    assert String('Test', mutations='commands').num_mutations() < String('Test').num_mutations()


def test_string_original_value(test_string):
    test_string.mutate()
    assert test_string.original_value == b'Test'


def test_string_filename(tmpdir):

    mutations = (
        'test1\n'
        'test2\n'
        'test3\n'
    )
    tmpfile = os.path.join(tmpdir, 'string_mutations.txt')
    print(tmpfile)
    with open(tmpfile, 'w') as f:
        f.write(mutations)

    s = String('Test', filename=tmpfile)
    s.mutate()
    assert s.render() == b'test1'

    s.mutate()
    assert s.render() == b'test2'

    assert s.num_mutations() == 3, "num mutations is not 3 and the file should have 3 mutations"


