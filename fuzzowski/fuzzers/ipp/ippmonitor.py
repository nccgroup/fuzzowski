from fuzzowski.monitors.imonitor import IMonitor
from fuzzowski import Session
from fuzzowski.connections import ITargetConnection

class IPPMon(IMonitor):
    get_printer_attribs_headers = ("POST {} HTTP/1.1\r\n"
                                   "Host: {}\r\n"
                                   "Accept-Encoding: identity\r\n"
                                   "Content-Type: application/ipp\r\n"
                                   "Connection: close\r\n"
                                   "User-Agent: Fuzzowski Mon\r\n"
                                   "Content-Length: 152\r\n"
                                   "\r\n"
                                   )

    get_printer_attribs_body = (b"\x01\x01"  # version-number
                                b"\x00\x0b"  # operation-id - Get-Printer-Attributes
                                b"\x00\x01\xab\x10"  # request-id
                                b"\x01"  # begin-attribute-group-tag

                                b"\x47"  # value-tag - charset
                                b"\x00\x12"  # name-length
                                b"attributes-charset"  # name
                                b"\x00\x05"  # value-length
                                b"utf-8"  # value

                                b"\x48"  # value-tag - natural language
                                b"\x00\x1b"
                                b"attributes-natural-language"
                                b"\x00\x02"
                                b"en"

                                b"\x45"  # value-tag - uri
                                b"\x00\x0b"
                                b"printer-uri"
                                b"\x00\x14"
                                b"ipp://localhost/ipp/"

                                b"\x44"  # value-tag - keyword
                                b"\x00\x14"
                                b"requested-attributes"
                                b"\x00\x13"
                                b"printer-description"
                                b"\x03"  # end-of-attributes-tag
                                )

    def __init__(self, session: Session, path: str = '/'):
        super().__init__(session)
        self.path = path

    @staticmethod
    def name() -> str:
        return "IPPMon"

    @staticmethod
    def help():
        return "Sends a get-attributes IPP message to the target"

    def test(self) -> bool:
        conn = self.get_connection_copy()
        result = self._get_ipp_attribs(conn)
        return result

    def _get_ipp_attribs(self, conn: ITargetConnection):
        try:
            conn.open()
            headers = self.get_printer_attribs_headers.format(self.path, conn.info).encode()
            conn.send(headers + self.get_printer_attribs_body)
            recv = conn.recv_all(10000)
            if len(recv) == 0:
                self.logger.log_error("Get Printer Attributes Failed!!")
                result = False
            else:
                self.logger.log_info(f"Get Printer Attributes succeeded")
                result = True
        except Exception as e:
            self.logger.log_error(f"Get Printer Attributes Failed!! Exception while receiving: {type(e).__name__}. {str(e)}")
            result = False
        finally:
            conn.close()

        return result
