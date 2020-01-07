from fuzzowski.monitors.imonitor import IMonitor
from fuzzowski.connections import ITargetConnection

# --------------------------------------------------------------- #
SlaveID = 1 # Modbus TCP Unit Identifier: 1..247
# --------------------------------------------------------------- #

# ----------------- Device ID to bytes -------------------------- #
def bitDeviceID(DeviceID):
    bytes_id = (DeviceID).to_bytes((DeviceID.bit_length() + 7) // 8, byteorder='big')
    return bytes_id

HexSlaveID = bitDeviceID(SlaveID)

class modbusMonitor(IMonitor):
    """
    MODBUS Monitor Module interface
    @Author: https://github.com/1modm
    """

    # Based on https://svn.nmap.org/nmap/scripts/modbus-discover.nse
    # Send Read Device Identification 
    get_modbus_device_id_nse = (b"\x00\x00"  # Modbus TCP Transaction Identifier
                               b"\x00\x00"  # Modbus TCP Protocol Identifier
                               b"\x00\x05"  # Modbus TCP Length
                               # Modbus TCP Unit Identifier
                               + HexSlaveID +
                               # Discover device ID
                               b"\x2b"  # Modbus Function Code: Encapsulated Interface Transport
                               b"\x0e"  # Modbus MEI type: Read Device Identification
                               b"\x01"  # Modbus Read Device ID: Basic Device Identification
                               b"\x00"  # Modbus Object ID: VendorName
                               )

    # Send Report Slave ID request
    get_modbus_slave_id = (b"\x00\x00"  # Modbus TCP Transaction Identifier
                           b"\x00\x00"  # Modbus TCP Protocol Identifier
                           b"\x00\x02"  # Modbus TCP Length
                           # Modbus TCP Unit Identifier
                           + HexSlaveID +  
                           b"\x11"  # Report Slave ID
                           #b"\x04", # Send read input register instead previous?
                           )

    @staticmethod
    def name() -> str:
        return "modbusMon"

    @staticmethod
    def help():
        return "Sends a query for MODBUS device id to the target and check the response"

    def test(self):
        conn = self.get_connection_copy()
        result = self._get_modbus_info(conn)
        return result


    def _get_modbus_info(self, conn: ITargetConnection):
        try:
            conn.open()
            conn.send(self.get_modbus_device_id_nse) # or get_modbus_slave_id
            data = conn.recv_all(10000)
            if len(data) == 0:
                self.logger.log_error("MODBUS error response, getting MODBUS device information Failed!!")
                result = False
            else:
                Unit_ID = data[6].to_bytes((data[6].bit_length() + 7) // 8, byteorder='big')
                Func_code = data[7]
                Exception_code = data[8]

                if data[5] > 0 and Unit_ID == HexSlaveID:
                    if hex(Func_code) == '0x11':
                      self.logger.log_info(f"Getting MODBUS device information succeeded")
                    elif hex(Exception_code) == '0xb': # more details needed? and (hex(Func_code) == '0x91' or hex(Func_code) == '0x84')
                      self.logger.log_warn(f"Getting MODBUS device information: Gateway target device failed to respond")
                    elif hex(Exception_code) == '0x1':
                      self.logger.log_warn(f"Getting MODBUS device information: Illegal function")
                    else:
                      self.logger.log_warn(f"Getting MODBUS device information warning")
                else:
                  self.logger.log_warn(f"Getting MODBUS data error")

                result = True
        except Exception as e:
            self.logger.log_error(f"MODBUS response error, getting MODBUS device information Failed!! Exception while receiving: {type(e).__name__}. {str(e)}")
            result = False
        finally:
            conn.close()

        return result