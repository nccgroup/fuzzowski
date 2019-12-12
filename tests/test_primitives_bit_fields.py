import pytest
from fuzzowski.mutants.primitives.bit_field import BitField
from fuzzowski.mutants.primitives.byte import Byte
from fuzzowski.mutants.primitives.word import Word
from fuzzowski.mutants.primitives.dword import DWord
from fuzzowski.mutants.primitives.qword import QWord
from fuzzowski.constants import LITTLE_ENDIAN, BIG_ENDIAN


@pytest.mark.parametrize("value, width, endian, rendered", [
    (30, 8, LITTLE_ENDIAN, b'\x1e'),
    (255, 8, LITTLE_ENDIAN, b'\xff'),
    (255, 8, BIG_ENDIAN, b'\xff'),
    (255, 16, LITTLE_ENDIAN, b'\xff\x00'),
    (255, 16, BIG_ENDIAN, b'\x00\xff'),
])
def test_bit_fields(value, width, endian, rendered):
    assert BitField(value, width=width, endian=endian).render() == rendered


def test_string_init():
    b = BitField(30, width=8, endian=LITTLE_ENDIAN)
    assert next(b) == b.render()


@pytest.fixture
def test_bit_field_little():
    return BitField(30, width=16, endian=LITTLE_ENDIAN, output_format='binary')


@pytest.fixture
def test_bit_field_big():
    return BitField(30, width=16, endian=BIG_ENDIAN, output_format='binary')


def test_bit_fields_big_endian(test_bit_field_big):
    assert test_bit_field_big.render() == test_bit_field_big.original_value

    assert test_bit_field_big.num_mutations == len([x for x in test_bit_field_big]) \
                                            == len([x for x in test_bit_field_big.mutation_generator(0)])

    gen = test_bit_field_big.mutation_generator(0)
    assert next(gen) == b'\x00\x00'
    assert next(gen) == b'\x00\x01'


def test_bit_fields_little_endian(test_bit_field_little):
    assert test_bit_field_little.render() == test_bit_field_little.original_value

    gen = test_bit_field_little.mutation_generator(0)
    assert next(gen) == b'\x00\x00'
    assert next(gen) == b'\x01\x00'


def test_bit_fields_reset():
    b = BitField(30, width=16, endian=BIG_ENDIAN, output_format='binary', mutations=[0, 1, 255, 0xffff])
    gen = b.mutation_generator(0)
    assert b.render() == b'\x00\x1e' == b.original_value

    actual_value = next(gen)
    assert b.render() == b'\x00\x00' == actual_value

    actual_value = next(gen)
    assert b.render() == b'\x00\x01' == actual_value

    gen = b.mutation_generator()  # Another generator, but without index, it will be reset
    actual_value = next(gen)
    assert b.render() == b'\x00\x00' == actual_value

    assert [x for x in b] == [b'\x00\x00', b'\x00\x01', b'\x00\xff', b'\xff\xff']


def test_bit_field_ascii():
    b = BitField(30, width=16, endian=BIG_ENDIAN, output_format='ascii', mutations=[0, 1, 255, 0xffff])
    assert [x for x in b] == [b'0', b'1', b'255', b'65535']


@pytest.mark.parametrize("value, rendered", [
    (30, b'\x1e'),
    (b'\x1e', b'\x1e'),
    (255, b'\xff'),
    (b'\xff', b'\xff'),
])
def test_byte(value, rendered):
    assert Byte(value).render() == Byte(value).original_value == rendered


@pytest.mark.parametrize("value, rendered", [
    (0, b'\x00\x00'),
    (b'\x01\x02', b'\x01\x02'),
    (255, b'\xff\x00'),
    (256, b'\x00\x01'),
    (b'\xff\xff', b'\xff\xff'),
])
def test_word(value, rendered):
    assert Word(value).render() == Word(value).original_value == rendered


@pytest.mark.parametrize("value, rendered", [
    (0, b'\x00\x00\x00\x00'),
    (255, b'\xff\x00\x00\x00'),
    (256, b'\x00\x01\x00\x00'),
    (b'\xff\xff\xff\xff', b'\xff\xff\xff\xff'),
    (b'\x00\x01\x00\x00', b'\x00\x01\x00\x00'),
])
def test_dword(value, rendered):
    assert DWord(value).render() == DWord(value).original_value == rendered


@pytest.mark.parametrize("value, rendered", [
    (0, b'\x00\x00\x00\x00\x00\x00\x00\x00'),
    (255, b'\xff\x00\x00\x00\x00\x00\x00\x00'),
    (256, b'\x00\x01\x00\x00\x00\x00\x00\x00'),
    (b'\xff\xff\xff\xff\xff\xff\xff\xff', b'\xff\xff\xff\xff\xff\xff\xff\xff'),
    (b'\x00\x01\x00\x00\x00\x01\x00\x00', b'\x00\x01\x00\x00\x00\x01\x00\x00'),
])
def test_qword(value, rendered):
    assert QWord(value).render() == QWord(value).original_value == rendered
