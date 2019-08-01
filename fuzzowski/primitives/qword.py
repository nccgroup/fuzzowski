import struct

from .bit_field import BitField, LITTLE_ENDIAN


class QWord(BitField):
    """QWord is a 8 Bytes sized BitField"""
    def __init__(self, value, *args, **kwargs):
        width = 64
        max_num = None

        aux_value = value
        if type(aux_value) not in [int, list, tuple]:
            assert len(aux_value) == 8, "Word value length must be 8!"
            aux_value = struct.unpack(LITTLE_ENDIAN + "Q", aux_value)[0]

        super(QWord, self).__init__(aux_value, width, max_num, *args, **kwargs)
