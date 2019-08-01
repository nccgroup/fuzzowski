import pytest
from fuzzowski import BitField, Byte, Word, DWord, QWord, LITTLE_ENDIAN, BIG_ENDIAN


@pytest.mark.parametrize("value, width, endian, rendered", [
    (30, 8, LITTLE_ENDIAN, b'\x1e'),
    (255, 8, LITTLE_ENDIAN, b'\xff'),
    (255, 8, BIG_ENDIAN, b'\xff'),
    (255, 16, LITTLE_ENDIAN, b'\xff\x00'),
    (255, 16, BIG_ENDIAN, b'\x00\xff'),
])
def test_bit_fields(value, width, endian, rendered):
    assert BitField(value, width=width, endian=endian).render() == rendered


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
