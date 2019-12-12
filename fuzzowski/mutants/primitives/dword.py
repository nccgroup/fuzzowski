import struct

from .bit_field import BitField, LITTLE_ENDIAN


class DWord(BitField):
    def __init__(self, value: bytes, *args, **kwargs):
        """
        DWord is a 4 Bytes sized BitField

        Args:
            value:      byte value (len 4)
            *args:      (Optional) BitField args
            **kwargs:   (Optional) BitField kwargs
        """
        # Inject our width argument
        width = 32
        max_num = None

        aux_value = value
        if type(aux_value) not in [int, list, tuple]:
            assert len(aux_value) == 4, "Word value length must be 4!"
            aux_value = struct.unpack(LITTLE_ENDIAN + "L", aux_value)[0]

        super(DWord, self).__init__(aux_value, width, max_num, *args, **kwargs)
