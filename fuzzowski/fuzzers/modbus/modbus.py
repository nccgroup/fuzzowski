from fuzzowski.fuzzers.ifuzzer import IFuzzer
from fuzzowski.mutants.spike import *
from fuzzowski import *
from fuzzowski import Session


class MODBUS(IFuzzer):
    """
    MODBUS Fuzzing Module
    Use at your own risk, and please do not use in a production environment
    @Author: https://github.com/1modm

    Based on https://github.com/youngcraft/boofuzz-modbus
    and https://github.com/riptideio/pymodbus

    virtualenv venv -p python3
    source venv/bin/activate
    pip install -r requirements.txt

    python -m fuzzowski 127.0.0.1 502 -p tcp -f modbus -rt 0.5 -r read_coil
    python -m fuzzowski 127.0.0.1 502 -p tcp -f modbus 
    python -m fuzzowski 127.0.0.1 502 -p tcp -f modbus -rt 1 -m modbusMon
    """

    # --------------------------------------------------------------- #

    name = 'modbus'

    @staticmethod
    def get_requests() -> List[callable]:
        return [MODBUS.read_coil, MODBUS.read_input, MODBUS.read_holding, MODBUS.read_discrete, MODBUS.single_coil, MODBUS.single_register, MODBUS.multiple_coil, MODBUS.multiple_register, MODBUS.other_operations]

    # --------------------------------------------------------------- #

    @staticmethod
    def define_nodes(*args, **kwargs) -> None:
        
        # ------------------ Read Coil Status (FC=01) ------------------- #

        s_initialize("modbus_read_coil")
        with s_block("modbus_head"):
            s_word(0x0001,name='transId',fuzzable=True)
            s_word(0x0000,name='protoId',fuzzable=False)
            s_word(0x06,endian='>',name='length')
            s_byte(0xff,name='unit Identifier',fuzzable=False)
            with s_block('pdu'):
                s_byte(0x01,name='funcCode read coil memory',fuzzable=False)
                s_word(0x0000,name='start address')
                s_word(0x0000,name='quantity')
        

        s_initialize('read_holding_registers')
        with s_block("modbus_head"):
            s_word(0x0001,name='transId',fuzzable=True)
            s_word(0x0002,name='protoId',fuzzable=False)
            s_word(0x06,endian='>',name='length')
            s_byte(0xff,name='unit Identifier',fuzzable=False)
            with s_block('read_holding_registers_block'):
                s_byte(0x01,name='read_holding_registers')
                s_word(0x0000,name='start address')
                s_word(0x0000,name='quantity')
        # --------------------------------------------------------------- #


        # ------------------ Read Input Status (FC=02) ------------------ #
        s_initialize('ReadDiscreteInputs')
        with s_block("modbus_head"):
            s_word(0x0001,name='transId',fuzzable=True)
            s_word(0x0002,name='protoId',fuzzable=False)
            s_word(0x06,endian='>',name='length')
            s_byte(0xff,name='unit Identifier',fuzzable=False)
            with s_block('ReadDiscreteInputsRequest'):
                s_byte(0x02,name='funcCode',fuzzable=False)
                s_word(0x0000,name='start_address')
                s_word(0x0000,name='quantity')
        # --------------------------------------------------------------- #

        # ---------------- Read Holding Registers (FC=03) --------------- #
        s_initialize('ReadHoldingRegisters')
        with s_block("modbus_head"):
            s_word(0x0001,name='transId',fuzzable=True)
            s_word(0x0002,name='protoId',fuzzable=False)
            s_word(0x06,endian='>',name='length')
            s_byte(0xff,name='unit Identifier',fuzzable=False)
            with s_block('ReadHoldingRegistersRequest'):
                s_byte(0x03,name='funcCode',fuzzable=False)
                s_word(0x0000,name='start_address')
                s_word(0x0000,name='quantity')
        # --------------------------------------------------------------- #

        # ---------------- Read Input Registers (FC=04) ----------------- #
        s_initialize('ReadInputRegisters')
        with s_block("modbus_head"):
            s_word(0x0001,name='transId',fuzzable=True)
            s_word(0x0002,name='protoId',fuzzable=False)
            s_word(0x06,endian='>',name='length')
            s_byte(0xff,name='unit Identifier',fuzzable=False)
            with s_block('ReadInputRegistersRequest'):
                s_byte(0x04,name='funcCode',fuzzable=False)
                s_word(0x0000,name='start_address')
                s_word(0x0000,name='quantity')
        # --------------------------------------------------------------- #


        # ------------------ Force Single Coil (FC=05) ------------------ #
        s_initialize('WriteSingleCoil')
        with s_block("modbus_head"):
            s_word(0x0001,name='transId',fuzzable=True)
            s_word(0x0002,name='protoId',fuzzable=False)
            s_word(0x06,endian='>',name='length')
            s_byte(0xff,name='unit Identifier',fuzzable=False)
            with s_block('WriteSingleCoilRequest'):
                s_byte(0x05,name='funcCode',fuzzable=False)
                s_word(0x0000,name='start_address')
                s_word(0x0000,name='quantity')
        # --------------------------------------------------------------- #

        # ---------------- Preset Single Register (FC=06) --------------- #

        s_initialize('WriteSingleRegister')
        with s_block("modbus_head"):
            s_word(0x0001,name='transId',fuzzable=True)
            s_word(0x0002,name='protoId',fuzzable=False)
            s_word(0x06,endian='>',name='length')
            s_byte(0xff,name='unit Identifier',fuzzable=False)
            with s_block('WriteSingleRegisterRequest'):
                s_byte(0x06,name='funcCode',fuzzable=False)
                s_word(0x0000,name='output_address')
                s_word(0x0000,name='output_value')
        # --------------------------------------------------------------- #

        # ---------------- Force Multiple Coils (FC=15) ----------------- #
        s_initialize('WriteMultipleCoils')
        with s_block("modbus_head"):
            s_word(0x0001,name='transId',fuzzable=True)
            s_word(0x0002,name='protoId',fuzzable=False)
            s_word(0x06,endian='>',name='length')
            s_byte(0xff,name='unit Identifier',fuzzable=False)
            with s_block('WriteMultipleCoilsRequest'):
                s_byte(0x0f,name='func_code',fuzzable=False)
                s_word(0x0000,name='starting_address')
                s_dword(0x0000,name='byte_count')
                s_size("outputsValue", length=8)
                with s_block("outputsValue"):
                    s_word(0x00,name='outputs_value')
        # --------------------------------------------------------------- #

        # --------------- Preset Multiple Registers (FC=16) ------------- #
        s_initialize('WriteMultipleRegisters')
        with s_block("modbus_head"):
            s_word(0x0001,name='transId',fuzzable=True)
            s_word(0x0002,name='protoId',fuzzable=False)
            s_word(0x06,endian='>',name='length')
            s_byte(0xff,name='unit Identifier',fuzzable=False)
            with s_block('WriteMultipleRegistersRequest'):
                s_byte(0x10,name='func_code',fuzzable=False)
                s_word(0x0000,name='starting_address')
                s_dword(0x0000,name='byte_count')
                s_size("outputsValue", length=16, name="outputsValue_1")
                s_size("outputsValue", length=8, name="outputsValue_2")
                with s_block("outputsValue"):
                    s_dword(0x0000,name='outputs_value')
        # --------------------------------------------------------------- #


        # ---------------------------- Other ---------------------------- #
        s_initialize('ReadExceptionStatus')
        with s_block("modbus_head"):
            s_word(0x0001,name='transId',fuzzable=True)
            s_word(0x0002,name='protoId',fuzzable=False)
            s_word(0x06,endian='>',name='length')
            s_byte(0xff,name='unit Identifier',fuzzable=False)
            with s_block('ReadExceptionStatusRequest'):
                s_byte(0x07,name='funcCode',fuzzable=False)
    
        s_initialize('ReadExceptionStatusError')
        with s_block("modbus_head"):
            s_word(0x0001,name='transId',fuzzable=True)
            s_word(0x0002,name='protoId',fuzzable=False)
            s_word(0x06,endian='>',name='length')
            s_byte(0xff,name='unit Identifier',fuzzable=False)
            with s_block('ReadExceptionStatusErrorRequest'):
                s_byte(0x87,name='funcCode',fuzzable=False)

        s_initialize('ReportSlaveId')
        with s_block("modbus_head"):
            s_word(0x0001,name='transId',fuzzable=True)
            s_word(0x0002,name='protoId',fuzzable=False)
            s_word(0x06,endian='>',name='length')
            s_byte(0xff,name='unit Identifier',fuzzable=False)
            with s_block('ReportSlaveIdRequest'):
                s_byte(0x11,name='func_code',fuzzable=False)

        s_initialize('ReadFileSub')
        with s_block("modbus_head"):
            s_word(0x0001,name='transId',fuzzable=True)
            s_word(0x0002,name='protoId',fuzzable=False)
            s_word(0x06,name='length')
            s_byte(0xff,name='unit Identifier',fuzzable=False)
            with s_block('ReadFileSubRequest'):
                s_byte(0x06,name='refType',fuzzable=False)
                s_word(0x0001,name='fileNumber')
                s_word(0x0000,name='recordNumber')
                s_word(0x0000,name='recordLength')

        s_initialize('ReadFileRecord')
        with s_block("modbus_head"):
            s_word(0x0001,name='transId',fuzzable=True)
            s_word(0x0002,name='protoId',fuzzable=False)
            s_word(0x06,endian='>',name='length')
            s_byte(0xff,name='unit Identifier',fuzzable=False)
            with s_block('ReadFileRecordRequest'):
                s_byte(0x14,name='funcCode',fuzzable=False)
                s_byte(0x0001,name='byteCount')

        s_initialize('WriteFileSub')
        with s_block("modbus_head"):
            s_word(0x0001,name='transId',fuzzable=True)
            s_word(0x0002,name='protoId',fuzzable=False)
            s_word(0x06,endian='>',name='length')
            s_byte(0xff,name='unit Identifier',fuzzable=False)
            with s_block('WriteFileSubRequest'):
                s_byte(0x06,name='refType',fuzzable=False)
                s_word(0x0001,name='fileNumber')
                s_word(0x0000,name='recordNumber')
                # ---------------------------------
                # s_size is record
                s_size('recordData',length=16,name='recordLength')
                with s_block("recordData"):
                    s_word(0x0000,name='recordData_value')
                s_word(0x0000,name='recordLength_value')

        s_initialize('WriteFileRecord')
        with s_block("modbus_head"):
            s_word(0x0001,name='transId',fuzzable=True)
            s_word(0x0002,name='protoId',fuzzable=False)
            s_word(0x06,endian='>',name='length')
            s_byte(0xff,name='unit Identifier',fuzzable=False)
            with s_block('WriteFileRecordRequest'):
                s_byte(0x15,name='funcCode',fuzzable=False)
                s_byte(0x00,name='datalength')

        s_initialize('MaskWriteRegister')
        with s_block("modbus_head"):
            s_word(0x0001,name='transId',fuzzable=True)
            s_word(0x0002,name='protoId',fuzzable=False)
            s_word(0x06,endian='>',name='length')
            s_byte(0xff,name='unit Identifier',fuzzable=False)
            with s_block('MaskWriteRegisterRequest'):
                s_byte(0x96,name='funcCode',fuzzable=False)
                s_word(0x0000,name='refAddr')
                s_word(0xffff,name='andMask')
                s_word(0x0000,name='orMask')

        s_initialize('ReadWriteMultipleRegisters')
        with s_block("modbus_head"):
            s_word(0x0001,name='transId',fuzzable=True)
            s_word(0x0002,name='protoId',fuzzable=False)
            s_word(0x06,endian='>',name='length')
            s_byte(0xff,name='unit Identifier',fuzzable=False)
            with s_block('ReadWriteMultipleRegistersRequest'):
                s_byte(0x17,name='funcCode',fuzzable=False)
                s_word(0x0000,name='readStartingAddr')
                s_word(0x0001,name='readQuantityRegisters')
                s_word(0x0000,name='writeStartingAddr')
                s_size('writeQuantityRegisters', length=16, endian='>')
                s_size('writeQuantityRegisters', length=8, endian='>', name="byteCount", math=lambda x:2*x)
                with s_block('writeQuantityRegisters'):
                    s_size('modbus_head',length=2)

        # --------------------------------------------------------------- #



    # --------------------------------------------------------------- #

    @staticmethod
    def read_coil(session: Session) -> None:
        session.connect(s_get('modbus_read_coil'))
        session.connect(s_get('read_holding_registers'))

    @staticmethod
    def read_discrete(session: Session) -> None:
        session.connect(s_get('ReadDiscreteInputs'))

    @staticmethod
    def read_holding(session: Session) -> None:
        session.connect(s_get('ReadHoldingRegisters'))

    @staticmethod
    def read_input(session: Session) -> None:
        session.connect(s_get('ReadInputRegisters'))

    @staticmethod
    def single_coil(session: Session) -> None:
        session.connect(s_get('WriteSingleCoil'))

    @staticmethod
    def single_register(session: Session) -> None:
        session.connect(s_get('WriteSingleRegister'))

    @staticmethod
    def multiple_coil(session: Session) -> None:
        session.connect(s_get('WriteMultipleCoils'))

    @staticmethod
    def multiple_register(session: Session) -> None:
        session.connect(s_get('WriteMultipleRegisters'))

    @staticmethod
    def other_operations(session: Session) -> None:
        session.connect(s_get('ReadExceptionStatus'))
        session.connect(s_get('ReadExceptionStatusError'))
        session.connect(s_get('ReportSlaveId'))
        session.connect(s_get('ReadFileSub'))
        session.connect(s_get('ReadFileRecord'))
        session.connect(s_get('WriteFileSub'))
        session.connect(s_get('WriteFileRecord'))
        session.connect(s_get('MaskWriteRegister'))
        #session.connect(s_get('ReadWriteMultipleRegisters'))


