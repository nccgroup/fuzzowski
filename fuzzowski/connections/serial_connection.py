import serial
from . import IConnection


class SerialConnection(IConnection):

    def __init__(self, port: str, baudrate: int, timeout: float):  # TODO: Add other Serial parameters
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        self.serial: serial.Serial = None

    @staticmethod
    def name() -> str:
        return "serial"

    @staticmethod
    def help() -> str:
        return "Serial connection"

    def close(self):
        self.serial.close()

    def open(self):
        self.serial = serial.Serial(port=self.port, baudrate=self.baudrate, timeout=self.timeout)

    def recv(self, max_bytes: int) -> bytes or None:
        return self.serial.read(size=max_bytes)

    def recv_all(self, max_bytes: int) -> bytes or None:
        return self.serial.read_all()

    def send(self, data: bytes) -> int:
        self.serial.write(data)
        return len(data)

    @property
    def info(self) -> str:
        return f'{self.port}:{self.baudrate}'

