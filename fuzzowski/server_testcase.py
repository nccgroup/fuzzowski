import time
from typing import List, TYPE_CHECKING

from fuzzowski.graph import Edge
from fuzzowski.ip_constants import DEFAULT_MAX_RECV
from fuzzowski.mutants.blocks import Request
from fuzzowski import exception, helpers
from fuzzowski.testcase import TestCase

if TYPE_CHECKING:
    from fuzzowski.session import Session


class ServerTestCase(TestCase):
    """The difference with a normal test case is that we accept a connection, receive data, and then send a response"""


    def open_fuzzing_target(self, retry: bool = True):
        """
        Try to open the target, twice in case one fails, saving last case as suspect if something goes wrong,
        restarting the target if a restarter is defined, and waiting for the target to wake up after that.

        Args:
            retry: Not used in ServerTestCase
        """
        self.session.target.accept()

    def transmit(self, request: Request, callback_data: bytes = None, original: bool = False, receive=True):
        """
        Render and transmit a fuzzed node, process callbacks accordingly.

        Args:
            request: Request that is being fuzzed
            callback_data: callback data from a previous callback
            original: if True, will send the original value and not render
            receive: if True, it will try to receive data after sending the request

        Returns: None
        Raises: FuzzowskiTestCaseAborted when a transmission error occurs
        """

        # 1. RECEIVE DATA
        if receive:
            try:
                receive_failed = False
                error = ''

                # Receive data depending on the request receive strategy
                self.last_recv = self.session.target.recv_by_strategy(request, self.session)

                if not self.last_recv:  # Nothing received, probably conn reset
                    receive_failed = True
                    error = "Nothing received"
                    # raise exception.FuzzowskiTestCaseAborted("Receive failed. Aborting Test Case")
                elif len(request.responses) > 0:  # Data received, Responses defined
                    try:
                        self.logger.log_check("Parsing response with data received")
                        response_str = request.parse_response(self.last_recv)
                        self.logger.log_info(response_str)
                        receive_failed = False
                    except exception.FuzzowskiRuntimeError as e:  # Data received, Response do not match
                        self.logger.log_fail(str(e))  # Abort TestCase
                        receive_failed = False
                        raise exception.FuzzowskiTestCaseAborted(str(e))
                    except Exception as e:  # Any other exception not controlled by the Restarter module
                        self.logger.log_fail(str(e))
                        self.session.is_paused = True  # Pause the session if an uncontrolled error occurs
                        raise exception.FuzzowskiTestCaseAborted(str(e))
                else:  # Data received, no Responses defined
                    receive_failed = False

                if self.session.opts.check_data_received_each_request:
                    self.logger.log_check("Checking data received...")
                    if receive_failed:
                        # Assume a crash?
                        self.logger.log_fail(f"Nothing received from target. {error}")
                        self.session.add_suspect(self)
                        raise exception.FuzzowskiTestCaseAborted("Receive failed. Aborting Test Case")

            except exception.FuzzowskiTargetConnectionReset as e:  # Connection reset
                self.logger.log_info("Target connection reset.")
                if self.session.opts.check_data_received_each_request:
                    self.logger.log_fail("Target connection reset.")
                    self.add_error(e)
                    self.session.add_suspect(self)
                raise exception.FuzzowskiTestCaseAborted(str(e))
            except exception.FuzzowskiTargetConnectionAborted as e:
                msg = f"Target connection lost (socket error: {e.socket_errno} {e.socket_errmsg})"
                if self.session.opts.check_data_received_each_request:
                    self.logger.log_fail(msg)
                    self.add_error(e)
                    self.session.add_suspect(self)
                else:
                    self.logger.log_info(msg)
                raise exception.FuzzowskiTestCaseAborted(str(e))

        if callback_data:
            data = callback_data
        else:
            if original:
                data = request.original_value
            else:
                data = request.render()

        # 2. SEND DATA
        try:
            self.last_send = data
            self.session.target.send(data)
        except exception.FuzzowskiTargetConnectionReset as e:  # Connection was reset
            self.logger.log_info("Target connection reset.")
            condition = self.session.opts.ignore_transmission_errors if original \
                else self.session.opts.ignore_connection_issues_after_fuzz
            if not condition:
                self.add_error(e)
                self.session.add_suspect(self)
            raise exception.FuzzowskiTestCaseAborted(str(e))  # Abort TestCase, Connection Reset
        except exception.FuzzowskiTargetConnectionAborted as e:
            msg = f"Target connection lost (socket error: {e.socket_errno} {e.socket_errmsg})"
            condition = self.session.opts.ignore_transmission_errors if original \
                else self.session.opts.ignore_connection_issues_after_fuzz
            if condition:
                self.logger.log_info(msg)
            else:
                self.logger.log_fail(msg)
                self.add_error(e)
                self.session.add_suspect(self)
                raise exception.FuzzowskiTestCaseAborted(str(e))  # Abort TestCase, Connection Failed

        # 3. CLOSE CONNECTION?
