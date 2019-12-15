from ..ip_constants import DEFAULT_MAX_RECV
from ..loggers import FuzzLoggerText
from copy import deepcopy

class Target(object):
    """Target descriptor container.

    Takes an ITargetConnection and wraps send/recv with appropriate
    FuzzDataLogger calls.

    Contains a logger which is configured by Session.add_target().

    Example:
        tcp_target = Target(SocketConnection(host='127.0.0.1', port=17971))

    Args:
        connection (itarget_connection.ITargetConnection): Connection to system under test.
    """

    def __init__(self, connection, procmon=None, procmon_options=None, netmon=None):
        self._fuzz_data_logger = None

        self._target_connection = connection
        self.procmon = procmon
        self.netmon = netmon

        # set these manually once target is instantiated.
        self.vmcontrol = None
        self.netmon_options = {}
        if procmon_options is None:
            procmon_options = {}
        self.procmon_options = procmon_options
        self.vmcontrol_options = {}

    def close(self):
        """
        Close connection to the target.

        :return: None
        """
        self._fuzz_data_logger.log_info('Closing target connection...')
        self._target_connection.close()
        self._fuzz_data_logger.log_info('Connection closed.')

    def open(self):
        """
        Opens connection to the target. Make sure to call close!

        :return: None
        """
        self._fuzz_data_logger.log_info('Opening target connection ({0})...'.format(self._target_connection.info))
        self._target_connection.open()
        self._fuzz_data_logger.log_info('Connection opened.')

    def recv(self, max_bytes=DEFAULT_MAX_RECV):
        """
        Receive up to max_bytes data from the target.

        Args:
            max_bytes (int): Maximum number of bytes to receive.

        Returns:
            Received data.
        """
        if self._fuzz_data_logger is not None:
            self._fuzz_data_logger.log_info("Receiving...")

        data = self._target_connection.recv(max_bytes=max_bytes)

        if self._fuzz_data_logger is not None:
            self._fuzz_data_logger.log_recv(data)

        return data

    def recv_all(self, max_bytes=DEFAULT_MAX_RECV):
        """
        Receive up to max_bytes data from the target. Trying to receive everything

        Args:
            max_bytes (int): Maximum number of bytes to receive.

        Returns:
            Received data.
        """
        if self._fuzz_data_logger is not None:
            self._fuzz_data_logger.log_info("Receiving...")

        data = self._target_connection.recv_all(max_bytes=max_bytes)

        if self._fuzz_data_logger is not None:
            self._fuzz_data_logger.log_recv(data)

        return data

    def send(self, data):
        """
        Send data to the target. Only valid after calling open!

        Args:
            data: Data to send.

        Returns:
            None
        """
        if self._fuzz_data_logger is not None:
            self._fuzz_data_logger.log_send(data)

        num_sent = self._target_connection.send(data=data)

        if self._fuzz_data_logger is not None:
            self._fuzz_data_logger.log_info("{0} bytes sent".format(num_sent))

    def set_fuzz_data_logger(self, fuzz_data_logger):
        """
        Set this object's fuzz data logger -- for sent and received fuzz data.

        :param fuzz_data_logger: New logger.
        :type fuzz_data_logger: ifuzz_logger.IFuzzLogger

        :return: None
        """
        self._fuzz_data_logger = fuzz_data_logger

    # def get_monitor_copy(self):
    #
    #     new_target = Target(connection=deepcopy(self._target_connection))
    #     new_target.set_fuzz_data_logger(FuzzLoggerText(file_handle=open('/dev/null', 'a')))
    #     return new_target

    @property
    def target_connection(self):
        return self._target_connection



