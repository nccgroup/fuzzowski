import struct

from .bit_field import BitField, LITTLE_ENDIAN


class Byte(BitField):
    def __init__(self, value: bytes, *args, **kwargs):
        """
        Byte is a 8 bit sized BitField

        Args:
            value:      byte value (len 1)
            *args:      (Optional) BitField args
            **kwargs:   (Optional) BitField kwargs
        """

        # Inject the one parameter we care to pass in (width)
        width = 8
        max_num = None

        aux_value = value
        if type(aux_value) not in [int, list, tuple]:
            assert len(aux_value) == 1, "Byte value length must be 1!"
            aux_value = struct.unpack(LITTLE_ENDIAN + "B", aux_value)[0]

        super(Byte, self).__init__(aux_value, width, max_num, *args, **kwargs)
