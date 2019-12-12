import struct

from .bit_field import BitField, LITTLE_ENDIAN


class Word(BitField):
    def __init__(self, value: bytes, *args, **kwargs):
        """
        Word is a 2 Bytes sized BitField

        Args:
            value:      byte value (len 2)
            *args:      (Optional) BitField args
            **kwargs:   (Optional) BitField kwargs
        """
        # Inject our width argument
        width = 16
        max_num = None

        aux_value = value
        if type(aux_value) not in [int, list, tuple]:
            assert len(aux_value) == 2, "Word value length must be 2!"
            aux_value = struct.unpack(LITTLE_ENDIAN + "H", aux_value)[0]

        super(Word, self).__init__(aux_value, width, max_num, *args, **kwargs)
