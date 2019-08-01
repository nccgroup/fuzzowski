import math
import ssl
import struct
import sys
# import httplib
import socket
import errno
import telnetlib
# from future.utils import raise_

from .. import helpers
from .itarget_connection import ITargetConnection
from .. import ip_constants
from .. import exception

ETH_P_IP = 0x0800  # Ethernet protocol: Internet Protocol packet, see Linux if_ether.h docs for more details.


def _seconds_to_second_microsecond_struct(seconds):
    """Convert floating point seconds value to second/useconds struct used by socket library."""
    microseconds_per_second = 1000000
    whole_seconds = math.floor(seconds)
    whole_microseconds = math.floor((seconds % 1) * microseconds_per_second)
    return struct.pack('ll', whole_seconds, whole_microseconds)


class TelnetConnection(ITargetConnection):
    """ITargetConnection implementation using Telnet.

    """

    def __init__(self,
                 host,
                 port=23,
                 timeout=5.0,
                 username=b'USERNAME',
                 password=b'PASSWORD'  # TODO: POSITIONAL ARGS
                 ):

        self.host = host
        self.port = port
        self.timeout = timeout
        self.username = username
        self.password = password

        self._active_session = False

        self._client = None
        self._counter = 0

    def close(self):
        """
        Close connection to the target.

        Returns:
            None
        """
        # We are not really closing the connection
        # TODO: Change to session
        #self._client.close()
        #self._active_session = False
        self._counter += 1
        if self._counter % 10 == 0:  # Close connection every 10
            self._client.close()
            self._active_session = False

    def open(self):
        """
        Opens connection to the target. Make sure to call close!

        Returns:
            None
        """

        try:
            if self._active_session is False:
                self._client = telnetlib.Telnet(self.host, port=self.port, timeout=self.timeout)
                self._client.read_until(b'User name:')
                self._client.write(self.username + b'\r\n')
                self._client.read_until(b'User password:')
                self._client.write(self.password + b'\r\n')
                m = self._client.read_until(b'>')  # Todo: Implementation dependant
                self._active_session = True

        except socket.error as e:
            self._active_session = False
            if e.errno == errno.ECONNREFUSED:
                # raise exception.FuzzowskiTargetConnectionFailedError(e.message)
                raise exception.FuzzowskiTargetConnectionFailedError('ECONNREFUSED')
            elif e.errno == errno.EALREADY:
                raise exception.FuzzowskiTargetConnectionFailedError('EALREADY')
            elif e.errno == errno.EINPROGRESS:
                raise exception.FuzzowskiTargetConnectionFailedError('EINPROGRESS')
            else:
                raise
        except OSError as e:
            raise exception.FuzzowskiTargetConnectionFailedError(errno.errorcode(e.errno))

    def recv(self, max_bytes):
        """
        Receive up to max_bytes data from the target.

        Args:
            max_bytes (int): Maximum number of bytes to receive.

        Returns:
            Received data.
        """
        try:
            # return self._client.read_eager()
            return self._client.read_until(b'>', timeout=self.timeout)  # TODO: Implementation Dependant

        except socket.timeout:
            self._active_session = False
            data = b''
            # raise exception.FuzzowskiTargetRecvTimeout()
        except socket.error as e:
            self._active_session = False
            if e.errno == errno.ECONNABORTED:
                # raise(exception.FuzzowskiTargetConnectionAborted(socket_errno=e.errno, socket_errmsg=e.strerror), None, sys.exc_info()[2])
                raise exception.FuzzowskiTargetConnectionAborted(socket_errno=e.errno, socket_errmsg=e.strerror)  # .with_traceback(sys.exc_info()[2])
            elif (e.errno == errno.ECONNRESET) or \
                    (e.errno == errno.ENETRESET) or \
                    (e.errno == errno.ETIMEDOUT):
                # raise(exception.FuzzowskiTargetConnectionReset, None, sys.exc_info()[2])
                raise exception.FuzzowskiTargetConnectionReset  # .with_traceback(sys.exc_info()[2])
            elif e.errno == errno.EWOULDBLOCK or e.errno == errno.EAGAIN:  # timeout condition if using SO_RCVTIMEO or SO_SNDTIMEO
                # raise exception.FuzzowskiTargetRecvTimeout()
                data = b''
            else:
                raise

        return data

    def recv_all(self, max_bytes):
        return self.recv(max_bytes)

    def send(self, data):
        """
        Send data to the target. Only valid after calling open!
        Some protocols will truncate; see self.MAX_PAYLOADS.

        Args:
            data: Data to send.

        Returns:
            int: Number of bytes actually sent.
        """
        # try:
        #     data = data[:self.MAX_PAYLOADS[self.proto]]
        # except KeyError:
        #     pass  # data = data

        try:
            self._client.write(data)
            num_sent = len(data)
        except socket.error as e:
            self._active_session = False
            if e.errno == errno.ECONNABORTED:
                raise(exception.FuzzowskiTargetConnectionAborted(socket_errno=e.errno, socket_errmsg=e.strerror),
                       None, sys.exc_info()[2])
            elif (e.errno == errno.ECONNRESET) or \
                    (e.errno == errno.ENETRESET) or \
                    (e.errno == errno.ETIMEDOUT) or \
                    (e.errno == errno.EPIPE):
                raise(exception.FuzzowskiTargetConnectionReset(None, sys.exc_info()[2]))
                # raise(exception.FuzzowskiTargetConnectionReset, None, sys.exc_info()[2])
            else:
                raise
        # TODO: OSError:
        except (Exception, OSError) as e:
            self._active_session = False
            raise(exception.FuzzowskiTargetConnectionAborted(socket_errno=e.errno, socket_errmsg=e.strerror),
                   None, sys.exc_info()[2])
        return num_sent

    @property
    def info(self):
        return '{0}:{1}'.format(self.host, self.port)




