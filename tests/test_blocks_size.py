import pytest
import os
import struct

from fuzzowski.mutants.primitives.string import String
from fuzzowski.mutants.primitives.static import Static
from fuzzowski.mutants.blocks.size import Size
from fuzzowski.mutants.blocks.request import Request
from fuzzowski.mutants.blocks.block import Block


@pytest.fixture
def test_string(tmpdir):
    """Returns a String"""

    mutations = (
        '1\n'
        '5test\n'
        '9testtest\n'
        '12characters\n'
    )
    tmpfile = os.path.join(tmpdir, 'string_mutations.txt')
    with open(tmpfile, 'w') as f:
        f.write(mutations)

    return String('Test', name='test_string', filename=tmpfile, mutation_types=('file',))


@pytest.fixture
def test_request(test_string):
    request = Request('test_request')
    size = Size(test_string.name, request, length=2, output_format='binary', endian='>')
    request.push(test_string)
    request.push(size)
    return request


def test_sizes(test_request):
    string = test_request.stack[0]
    size = test_request.stack[1]

    assert _word_to_int(size.render(), '>') == len(string) == _word_to_int(size.original_value, '>')
    for mutation in string:
        assert _word_to_int(size.render(), '>') == len(string) == len(mutation)


@pytest.mark.parametrize("mutation_idx, size_int, size_value", [
    (0, 1,  b'\x00\x01'),
    (1, 5,  b'\x00\x05'),
    (2, 9,  b'\x00\x09'),
    (3, 12, b'\x00\x0c')
])
def test_sizes_mutations(mutation_idx, size_int, size_value, test_request):
    string = test_request.stack[0]
    size = test_request.stack[1]

    gen = test_request.mutation_generator(mutation_idx)
    req_value = next(gen)
    print(req_value, string.render(), size.render())
    assert size.render() == size_value
    assert _word_to_int(size.render(), '>') == size_int
    assert string.render() + size.render() == req_value


@pytest.mark.parametrize("mutation_idx, size_int, size_value, length, output_format, endian", [
    (0, 1,  b'\x01\x00\x00', 3, 'binary', '<'),
    (0, 1,  b'1', 3, 'ascii', '<'),
    (1, 5,  b'\x05', 1, 'binary', '<'),
    (1, 5,  b'\x05', 1, 'binary', '>'),
    (2, 9,  b'9', 3, 'ascii', '<'),
    (3, 12, b'\x0c\x00\x00\x00\x00', 5, 'binary', '<'),
    (3, 12, b'\x00\x00\x00\x00\x0c', 5, 'binary', '>')
])
def test_sizes_formats(mutation_idx, size_int, size_value, test_string, length, output_format, endian):
    test_request = Request('test_request')
    size = Size(test_string.name, test_request, length=length, output_format=output_format, endian=endian)
    test_request.push(test_string)
    test_request.push(size)

    string = test_request.stack[0]
    gen = test_request.mutation_generator(mutation_idx)
    req_value = next(gen)
    # print(req_value, string.render(), size.render())
    assert size.render() == size_value
    assert string.render() + size.render() == req_value


@pytest.mark.parametrize("length, output_format, endian, inclusive, mutation_idx, size_value", [
    # length    output_format  endian   inclusive   mutation_idx,   size_value
    (2,         'binary',       '<',    False,      1,              b'\x0a\x00'),  # test_string value is b'5test'
    (2,         'binary',       '<',    True,       1,              b'\x0c\x00'),  # test_string value is b'5test'
    (2,         'ascii',        '<',    False,      1,              b'10'),
    (2,         'ascii',        '<',    True,       1,              b'12'),
    (2,         'ascii',        '<',    True,       4,              b'0'),  # First size mutation, value should be 0
])
def test_size_blocks(test_string, length, output_format, endian, inclusive, mutation_idx, size_value):
    """
    Request
        Block
            String
            Static
        Size(Block)
    """
    test_request = Request('test_request')

    test_block = Block('test_block', test_request)
    test_block.push(test_string)
    static1 = Static(b'5char', name='size')
    test_block.push(static1)
    size = Size(test_block.name, test_request,
                length=length, output_format=output_format, endian=endian, inclusive=inclusive)
    test_request.push(test_block)
    test_request.pop()
    test_request.push(size)

    gen = test_request.mutation_generator(mutation_idx)
    req_value = next(gen)
    print(req_value, test_string.render(), size.render())
    assert size.render() == size_value
    assert test_string.render() + static1.render() + size.render() == req_value


def _word_to_int(word: bytes, endian: chr) -> int:
    return struct.unpack(endian + "H", word)[0]
