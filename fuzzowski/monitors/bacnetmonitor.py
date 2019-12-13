from .imonitor import IMonitor
from fuzzowski import Session
from ..connections import ITargetConnection
from time import sleep
from copy import deepcopy

class BACnetMonitor(IMonitor):
    """
    BACnet Monitor Module interface
    
    https://github.com/1modm
    """

    get_bacnet_property_identifier_id = (b"\x81"  # Type: BACnet/IP (Annex J)
                                   b"\x0a"  # Function: Original-Unicast-NPDU
                                   b"\x00\x11"  # BVLC-Length: 4 of 17 bytes
                                   # BACnet NPDU
                                   b"\x01"  # Version: 0x01 (ASHRAE 135-1995)
                                   b"\x04"  # Control (expecting reply)
                                   # BACnet APDU
                                   b"\x00"  # APDU Type: Confirmed-REQ, PDU flags: 0x0
                                   b"\x05"  # Max response segments unspecified, Max APDU size: 1476 octets
                                   b"\x01"  # Invoke ID: 1
                                   b"\x0c"  # Service Choice: readProperty
                                   b"\x0c"  # Context-specific tag, number 0, Length Value Type 4
                                   b"\x02\x3f\xff\xff" # Object Type: device; instance number 4194303
                                   b"\x19\x4b" # Context-specific tag, number 1, Length Value Type 1
                                   )

    def __init__(self, session: Session, *args, **kwargs):
        self.session = session

    @staticmethod
    def name() -> str:
        return "BACnetMon"

    @staticmethod
    def help():
        return "Discovers and enumerates BACnet devices and collects device information based off standard requests"

    def run(self):
        self.session.logger.open_test_step(f"Calling Monitor {self.name()}")
        conn = deepcopy(self.session.target._target_connection)
        result = self._get_bacnet_info(conn)
        return result

    def _get_bacnet_info(self, conn: ITargetConnection):
        conn.open()
        conn.send(self.get_bacnet_property_identifier_id)
        recv = conn.recv_all(10000)
        if len(recv) == 0:
            self.session.logger.log_error("BACnet error response, getting BACnet device information Failed!!")
            result = False
        else:
            self.session.logger.log_info(f"Getting BACnet device information succeeded")
            result = True

        conn.close()
        return result

