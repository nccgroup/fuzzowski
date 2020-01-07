from fuzzowski.fuzzers.ifuzzer import IFuzzer
from fuzzowski.mutants.spike import *
from fuzzowski import Session

"""
BACnet Fuzzing Module example
Use at your own risk, and please do not use in a production environment
@Author: https://github.com/1modm

Change your Device ID BACnet server below
"""

# --------------------------------------------------------------- #
DeviceID = 12345 # BACnet Device ID
# --------------------------------------------------------------- #

# ----------------- Device ID to bytes -------------------------- #
def bitDeviceID(DeviceID):
    bytes_id = (DeviceID).to_bytes((DeviceID.bit_length() + 7) // 8, byteorder='big')
    return bytes_id

HexDeviceID = bitDeviceID(DeviceID)

if len(HexDeviceID) == 1:
    DeviceID_byte1 = 0x00
    DeviceID_byte2 = 0x00
    DeviceID_byte3 = int(HexDeviceID[0])
if len(HexDeviceID) == 2:
    DeviceID_byte1 = 0x00
    DeviceID_byte2 = int(HexDeviceID[0])
    DeviceID_byte3 = int(HexDeviceID[1])
elif len(HexDeviceID) == 3:
    DeviceID_byte1 = int(HexDeviceID[0])
    DeviceID_byte2 = int(HexDeviceID[1])
    DeviceID_byte3 = int(HexDeviceID[2])
# --------------------------------------------------------------- #

BVLC_Function_Code = [
    '\x00',  # BVLC Result
    '\x01',  # Write Broadcast Distribution Table 
    '\x02',  # Read Broadcast Distribution Table 
    '\x03',  # Read Broadcast Distribution Table ACK 
    '\x04',  # Forwarded-NPDU
    '\x05',  # Register Foreign Device
    '\x0a',  # Original-Unicast-NPDU
    '\x0b',  # Original-Broadcast-NPDU
    '\x0c'   # Secure-BVLL 
]

Confirmed_Service_Choices = [
    '\x05',  # Subscribe COV
    '\x0c',  # Read Property
    '\x0e',  # Read Property Multiple
    '\x0f',  # Write Property 
    '\x10',  # Write Property Multiple
    '\x11',  # Device Communication Control
    '\x14'   # Reinitialize Device
]

Network_Layer_Message_Type = [
    '\x00',  # Who-Is-Router-To-Network
    '\x01',  # I-Am-Router-To-Network
    '\x02',  # I-Could-Be-Router-To-Network
    '\x03',  # Reject-Message-To-Network
    '\x04',  # Router-Busy-To-Network
    '\x05',  # Router-Available-To-Network 
    '\x06',  # Initialize-Routing-Table
    '\x07',  # Initialize-Routing-Table-ACK
    '\x08',  # Establish-Connection-To-Network
    '\x09',  # Disconnect-Connection-To-Network
    '\x0a',  # Challenge-Request
    '\x0b',  # Security-Payload
    '\x0c',  # Security-Response
    '\x0d',  # Request-Key-Update
    '\x0e',  # Update-Key-Set
    '\x0f',  # Update-Distribution-Key
    '\x10',  # Request-Master-Key
    '\x11'  # Set-Master-Key
    # 0x12 to 0x7F Reserved for use by ASHRAE
    # 0x80 to 0xFF Available for Vendor Proprietary Messages
]

class BACnet(IFuzzer):
    """
    BACnet Fuzzing Module example

    virtualenv venv -p python3
    source venv/bin/activate
    pip install -r requirements.txt

    python -m fuzzowski 127.0.0.1 47808 -p udp -f bacnet -rt 0.5 -m BACnetMon
    python -m fuzzowski 127.0.0.1 47808 -p udp -f bacnet -rt 0.5 -r who_is -m BACnetMon
    python -m fuzzowski 127.0.0.1 47808 -p udp -f bacnet -rt 0.5 -r DeviceCommunicationControl -m BACnetMon
    """

    name = 'bacnet'

    @staticmethod
    def get_requests() -> List[callable]:
        return [BACnet.DeviceCommunicationControl, BACnet.who_is, BACnet.i_Am, BACnet.Initialize_Routing_Table, BACnet.Who_Is_Router_To_Network, BACnet.readProperty, BACnet.atomicReadFile, BACnet.atomicWriteFile]

    @staticmethod
    def define_nodes(*args, **kwargs) -> None:
        
        # ---------------- DeviceCommunicationControl ------------------- #
        # Used in CVE-2019-12480
        # Start DeviceCommunicationControl bacnet request packet
        s_initialize("DeviceCommunicationControl")
        with s_block("bacnet_virtual_link_control"):
            s_byte(0x81, name='type_bvlc', fuzzable=False)
            s_byte(0x0a, name='function_bvlc', fuzzable=False)
            s_word(0x0017, name='length_bvlc', endian='>', fuzzable=True)
        with s_block("bacnet_npdu"):
            s_byte(0x01, name='version_bacnet', fuzzable=False)
            s_byte(0x04, name='control_bacnet', fuzzable=False)
        with s_block("bacnet_apdu"):
            s_byte(0x02, name='type_bacapp', fuzzable=True)
            s_byte(0x44, name='max_adpu_size_bacapp', fuzzable=True)
            s_byte(0x08, name='invoke_id_bacapp', fuzzable=True)
            s_byte(0x11, name='confirmed_service_bacapp', fuzzable=True)
            s_byte(0x0d, name='context_tag', fuzzable=True)
            s_byte(0xff, name='tag_class', fuzzable=True)
            s_byte(0x80, name='tag_number', fuzzable=True)
            s_word(0x0000, name='enable', endian='>', fuzzable=True)
            s_word(0x0000, name='passwd_length', endian='>', fuzzable=True)
            s_byte(0x00, name='lvt', fuzzable=True)
            s_dword(0x0a1a0300, name='lenght_value_type', endian='>', fuzzable=True)
            s_word(0x1900, name='enable-disable', endian='>', fuzzable=True)
            s_byte(0x2a, name='lvt_passwd', fuzzable=True)
            s_byte(0x00, name='string_char_set', fuzzable=True)
            s_string('A', name='passwd', fuzzable=True)
        # end bacnet DeviceCommunicationControl
        # ---------------- DeviceCommunicationControl ------------------- #
        
        # ------------------------- Who-Is ------------------------------ #
        # Start Who-Is bacnet request packet
        s_initialize("who_is")
        with s_block("bacnet_virtual_link_control"):
            s_byte(0x81, name='type_bvlc', fuzzable=False)
            s_byte(0x0b, name='function_bvlc', fuzzable=False)
            s_word(0x000c, name='length_bvlc', endian='>', fuzzable=True)
        with s_block("bacnet_npdu"):
            s_byte(0x01, name='version_bacnet', fuzzable=True)
            s_byte(0x20, name='control_bacnet', fuzzable=True)
            s_word(0xffff, name='detination', endian='>', fuzzable=True)
            s_byte(0x00, name='mac', fuzzable=True)
            s_byte(0xff, name='hop', fuzzable=True)
        with s_block("bacnet_apdu"):
            s_byte(0x10, name='type_bacapp', fuzzable=True)
            s_byte(0x08, name='confirmed_service_bacapp', fuzzable=True)
        # end
        # ------------------------- Who-Is ------------------------------ #

        # ------------------- Initialize_Routing_Table ------------------ #
        # Start Initialize_Routing_Table bacnet request packet
        s_initialize("Initialize_Routing_Table")
        with s_block("bacnet_virtual_link_control"):
            s_byte(0x81, name='type_bvlc', fuzzable=False)
            s_byte(0x0b, name='function_bvlc', fuzzable=False)
            s_word(0x0008, name='length_bvlc', endian='>', fuzzable=True)
        with s_block("bacnet_npdu"):
            s_byte(0x01, name='version_bacnet', fuzzable=True)
            s_byte(0x80, name='control_bacnet', fuzzable=True)
            s_byte(0x06, name='message_type', fuzzable=True)
            s_byte(0x00, name='rpot_number', fuzzable=True)
        # end
        # ------------------- Initialize_Routing_Table ------------------ #


        # ------------------ Who_Is_Router_To_Network ------------------- #
        # Start Who_Is_Router_To_Network bacnet request packet 
        s_initialize("Who_Is_Router_To_Network")
        with s_block("bacnet_virtual_link_control"):
            s_byte(0x81, name='type_bvlc', fuzzable=False)
            s_byte(0x0b, name='function_bvlc', fuzzable=False)
            s_word(0x0007, name='length_bvlc', endian='>', fuzzable=True)
        with s_block("bacnet_npdu"):
            s_byte(0x01, name='version_bacnet', fuzzable=True)
            s_byte(0x80, name='control_bacnet', fuzzable=True)
            s_byte(0x00, name='message_type', fuzzable=True)
        # end
        # ------------------ Who_Is_Router_To_Network ------------------- #
        
        # ---------------------------- i-Am ----------------------------- #
        # Start i-Am bacnet request packet 
        s_initialize("i_Am")
        with s_block("bacnet_virtual_link_control"):
            s_byte(0x81, name='type_bvlc', fuzzable=False)
            s_byte(0x0b, name='function_bvlc', fuzzable=False)
            s_word(0x0018, name='length_bvlc', endian='>', fuzzable=True)
        with s_block("bacnet_npdu"):
            s_byte(0x01, name='version_bacnet', fuzzable=True)
            s_byte(0x20, name='control_bacnet', fuzzable=True)
            s_word(0xffff, name='destination', endian='>', fuzzable=True)
            s_byte(0x00, name='destination_mac', fuzzable=True)
            s_byte(0xff, name='hop_count', fuzzable=True)
        with s_block("bacnet_apdu"):
            s_byte(0x10, name='type_bacapp', fuzzable=True)
            s_byte(0x00, name='confirmed_service_bacapp', fuzzable=True)
            # deviceID
            s_byte(0xc4, name='ObjectIdentifier_device', fuzzable=True)
            s_byte(0x02, name='ObjectIdentifier_instance_number', fuzzable=True)
            s_byte(DeviceID_byte1, name='ObjectIdentifier_deviceID_byte1', fuzzable=True)
            s_byte(DeviceID_byte2, name='ObjectIdentifier_deviceID_byte2', fuzzable=True)
            s_byte(DeviceID_byte3, name='ObjectIdentifier_deviceID_byte3', fuzzable=True)
            # deviceID
            s_byte(0x22, name='lvt', fuzzable=True)
            s_word(0x0400, name='max_adpu_size_bacapp', endian='>', fuzzable=True)
            s_word(0x9100, name='segmented_both', endian='>', fuzzable=True)
            s_word(0x2105, name='vendor_id', endian='>', fuzzable=True)
        # end
        # ---------------------------- i-Am ----------------------------- #
        
        # ------------------------- readProperty ------------------------ #
        # Start readProperty bacnet request packet
        s_initialize("readProperty")
        with s_block("bacnet_virtual_link_control"):
            s_byte(0x81, name='type_bvlc', fuzzable=False)
            s_byte(0x0b, name='function_bvlc', fuzzable=False)
            s_word(0x0011, name='length_bvlc', endian='>', fuzzable=True)
        with s_block("bacnet_npdu"):
            s_byte(0x01, name='version', fuzzable=False)
            s_byte(0x04, name='control', fuzzable=False)
        with s_block("bacnet_apdu"):
            s_byte(0x02, name='type_bacapp', fuzzable=False)
            s_byte(0x44, name='max_adpu_size_bacapp', fuzzable=True)
            s_byte(0x03, name='invoke_id_bacapp', fuzzable=True)
            s_byte(0x0c, name='confirmed_service_bacapp', fuzzable=True)
            # deviceID
            s_byte(0x0c, name='ObjectIdentifier_deviceID', fuzzable=True)
            s_byte(0x02, name='ObjectIdentifier_instance_number', fuzzable=True)
            s_byte(DeviceID_byte1, name='ObjectIdentifier_deviceID_byte1', fuzzable=True)
            s_byte(DeviceID_byte2, name='ObjectIdentifier_deviceID_byte2', fuzzable=True)
            s_byte(DeviceID_byte3, name='ObjectIdentifier_deviceID_byte3', fuzzable=True)
            s_word(0x194b, name='property_identifier_bacapp', endian='>', fuzzable=True)
        # end
        # ------------------------- readProperty ------------------------ #

        # ------------------------- atomicReadFile ----------------------- #
        # Start atomicReadFile bacnet request packet
        s_initialize("atomicReadFile")
        with s_block("bacnet_virtual_link_control"):
            s_byte(0x81, name='type_bvlc', fuzzable=False)
            s_byte(0x0a, name='function_bvlc', fuzzable=False)
            s_word(0x001b, name='length_bvlc', endian='>', fuzzable=True)
        with s_block("bacnet_npdu"):
            s_byte(0x01, name='version', fuzzable=False)
            s_byte(0x04, name='control', fuzzable=False)
        with s_block("bacnet_apdu"):
            s_byte(0x00, name='type_bacapp', fuzzable=False)
            s_byte(0x05, name='max_adpu_size_bacapp', fuzzable=True)
            s_byte(0x01, name='invoke_id_bacapp', fuzzable=True)
            s_byte(0x06, name='confirmed_service_bacapp', fuzzable=True)
            # file
            s_dword(0xc4028000, name='file', endian='>', fuzzable=True)
            s_byte(0x00, name='ObjectIdentifier', fuzzable=True)
            # stream
            s_word(0x0e35, name='named_tag', endian='>', fuzzable=True)
            s_dword(0xffdf62ee, name='lvt', endian='>', fuzzable=True)
            s_byte(0x00, name='ObjectIdentifier_2', fuzzable=True)
            s_dword(0x00220584, name='text', endian='>', fuzzable=True)
            s_byte(0x0f, name='named_tag_2', fuzzable=True)
        # end
        # ------------------------- atomicReadFile ----------------------- #

        # ------------------------- atomicWriteFile ---------------------- #
        # Start atomicWriteFile bacnet request packet
        s_initialize("atomicWriteFile")
        with s_block("bacnet_virtual_link_control"):
            s_byte(0x81, name='type_bvlc', fuzzable=False)
            s_byte(0x0a, name='function_bvlc', fuzzable=False)
            s_word(0x001b, name='length_bvlc', endian='>', fuzzable=True)
        with s_block("bacnet_npdu"):
            s_byte(0x01, name='version', fuzzable=False)
            s_byte(0x04, name='control', fuzzable=False)
        with s_block("bacnet_apdu"):
            s_byte(0x00, name='type_bacapp', fuzzable=False)
            s_byte(0x05, name='max_adpu_size_bacapp', fuzzable=True)
            s_byte(0x02, name='invoke_id_bacapp', fuzzable=True)
            s_byte(0x07, name='confirmed_service_bacapp', fuzzable=True)
            # file
            s_dword(0xc4028000, name='file', endian='>', fuzzable=True)
            s_byte(0x00, name='ObjectIdentifier', fuzzable=True)
            # stream
            s_word(0x0e35, name='named_tag', endian='>', fuzzable=True)
            s_dword(0xff5ed5c0, name='lvt', endian='>', fuzzable=True)
            s_byte(0x85, name='ObjectIdentifier_2', fuzzable=True)
            s_dword(0x0a62640a, name='text', endian='>', fuzzable=True)
            s_byte(0x0f, name='named_tag_2', fuzzable=True)
        # end
        # ------------------------- atomicWriteFile ---------------------- #

    # --------------------------------------------------------------- #
      
    @staticmethod
    def who_is(session: Session) -> None:
        session.connect(s_get('who_is'))

    @staticmethod
    def i_Am(session: Session) -> None:
        session.connect(s_get('i_Am'))
        
    @staticmethod
    def Initialize_Routing_Table(session: Session) -> None:
        session.connect(s_get('Initialize_Routing_Table'))

    @staticmethod
    def Who_Is_Router_To_Network(session: Session) -> None:
        session.connect(s_get('Who_Is_Router_To_Network'))

    @staticmethod
    def readProperty(session: Session) -> None:
        session.connect(s_get('readProperty'))

    @staticmethod
    def atomicReadFile(session: Session) -> None:
        session.connect(s_get('atomicReadFile'))

    @staticmethod
    def atomicWriteFile(session: Session) -> None:
        session.connect(s_get('atomicWriteFile'))
        
    @staticmethod
    def DeviceCommunicationControl(session: Session) -> None:
        session.connect(s_get('DeviceCommunicationControl'))