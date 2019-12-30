import time
from typing import List, TYPE_CHECKING

from fuzzowski.graph import Edge
from fuzzowski.ip_constants import DEFAULT_MAX_RECV
from fuzzowski.mutants.blocks import Request
from fuzzowski import exception, helpers

if TYPE_CHECKING:
    from fuzzowski.session import Session


class TestCase(object):

    def __init__(self, id: int, session: 'Session', request: Request, path: List[Edge]):
        """
        The TestCase contains all the information to perform a test or show information about it.

        Args:
            id: a number (should be the mutation number of the session)
            session: The session file, as most options from the session are used
            request: The request that is being fuzzed
            path: The path of requests that is being fuzzed
        """
        self.id = id
        self.session = session
        self.request = request
        self.path = path

        self.logger = session.logger

        self.path_name = '->' \
            .join([edge.dst.name if edge.dst != self.request else f'[{edge.dst.name}]' for edge in self.path])
        self.name = f'{self.path_name}.{self.request.mutant.name}.{self.request.mutant_index}'
        self.short_name = f'{self.request.name}.{self.request.mutant.name}.{self.request.mutant_index}'
        self.errors = []

        self.request_name = self.request.name
        self.mutant_name = self.request.mutant.name

    def add_error(self, error):
        """ Add an error to the current case """
        self.errors.append(error)

    def run(self, fuzz: bool = True, retry: bool = True) -> bool:
        """
        Run the test case, transmitting the full path

        Args:
            fuzz:   (default True) Send the fuzzed node. If it is false, it transmit the original (for tests)
            retry:  (default True) Retry if connection fails

        Returns: True if the TestCase was run and data was transmitted (even if transmission was cut)
                 False if there was a connection issue and the target was paused, so the TestCase was not run
        """
        # First step is to open the target
        # TODO: Mechanism for not opening if want to keep an open connection between fuzzed packets
        #  (e.g. CLI in Telnet Session)
        try:
            self.logger.open_test_case(f"{self.id}: {self.name} {'[SENDING ORIGINAL]' if not fuzz else ''}",
                                       name=self.name, index=self.id)
            self.logger.log_info(
                f"Type: {type(self.request.mutant).__name__}. "
                f"Default value: {repr(self.request.mutant.original_value)}. "
                f"Case {self.id} of {self.session.num_mutations} overall.")

            self.open_fuzzing_target(retry=retry)

            fuzzed_sent = False
            for idx, edge in enumerate(self.path, start=1):  # Now we go through our path, sending each request
                request = edge.dst
                callback = edge.callback

                if request == self.request:
                    # This is the node we are fuzzing
                    if fuzz:
                        self.logger.open_test_step(f'Fuzzing node {request.name}')
                        callback_data = self._callback_current_node(node=request, edge=edge)
                        self.transmit(request, callback_data=callback_data)
                        fuzzed_sent = True
                    else:
                        self.logger.open_test_step(f'Transmit node {request.name}')
                        callback_data = self._callback_current_node(node=request, edge=edge, original=True)
                        self.transmit(request, callback_data=callback_data, original=True)

                else:
                    # This is a node we are not fuzzing right now
                    self.logger.open_test_step(f'Transmit node {request.name}')
                    callback_data = self._callback_current_node(node=request, edge=edge, original=True)
                    self.transmit(request, callback_data=callback_data, original=not fuzzed_sent)

                if self.session.opts.new_connection_between_requests and len(self.path) > idx:  # Reopen connection
                    try:
                        self.session.target.close()
                        self.open_fuzzing_target(retry=False)
                    except (exception.FuzzowskiTargetConnectionFailedError, Exception) as e:
                        self.add_error(e)
                        self.session.add_suspect(self)
                        raise exception.FuzzowskiTestCaseAborted(str(e))

            self.session.target.close()
            self.session.add_latest_test(self)
            return True
        except exception.FuzzowskiPaused:
            return False  # Returns False when the fuzzer got paused, as it did not run the TestCase
        except exception.FuzzowskiTestCaseAborted as e:  # There was a transmission Error, we end the test case
            self.logger.log_info(f'Test case aborted due to transmission error: {str(e)}')
            self.session.add_latest_test(self)
            return True

    def test(self):
        """Run a test case without fuzzing"""
        self.run(fuzz=False, retry=False)

    def open_fuzzing_target(self, retry: bool = True):
        """
        Try to open the target, twice in case one fails, saving last case as suspect if something goes wrong,
        restarting the target if a restarter is defined, and waiting for the target to wake up after that.

        Args:
            retry: Only retry, restart and wait for recover if retry is True
        """
        target = self.session.target

        try:
            target.open()
        except (exception.FuzzowskiTargetConnectionFailedError, Exception) as e:  # TimeoutError, socket.timeout
            if retry:  # Only retry, restart and wait for recover if retry is True
                try:
                    self.logger.log_fail("Cannot connect to target; Retrying... ")
                    target.open()  # Second try, just in case we have a network error not caused by the fuzzer
                except (exception.FuzzowskiTargetConnectionFailedError, Exception) as e:
                    self.logger.log_error("Cannot connect to target; target presumed down.")
                    self.session.add_last_case_as_suspect(e)
                    # raise
                    self.session.restart_target()  # Restart the target if a restarter was set
                    recovered = self.wait_until_target_recovered()  # Wait for target to recover
                    if recovered:
                        # target.open()  # Open a new connection, as the last one will be closed
                        self.open_fuzzing_target()
                    else:
                        raise

            else:  # Do not retry, raise the exception
                raise

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
        if callback_data:
            data = callback_data
        else:
            if original:
                data = request.original_value
            else:
                data = request.render()

        # 1. SEND DATA
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

        # 2. RECEIVE DATA
        if receive:
            try:
                receive_failed = False
                error = ''
                self.last_recv = self.session.target.recv_all(DEFAULT_MAX_RECV)
                if not self.last_recv:  # Nothing received, probably conn reset
                    receive_failed = True
                    error = "Nothing received. Connection Reset?"
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

    # --------------------------------------------------------------- #

    def wait_until_target_recovered(self):
        """
        Returns: bool indicating if the target has recovered (False happens if the session is paused before that)
        """
        # When the connection fails, we want to pause the fuzzer, save the packets,etc
        recovered = False
        if self.session.is_paused:
            raise exception.FuzzowskiPaused('Paused while waiting for recovery')
        self.logger.open_test_step('Waiting for target recovery')
        while not recovered:
            if self.session.is_paused:
                raise exception.FuzzowskiPaused('Paused while waiting for recovery')
            self.logger.log_info(f"Target seems down. Sleeping for {self.session.opts.restart_sleep_time} seconds")
            time.sleep(self.session.opts.restart_sleep_time)
            try:
                self.test()
                self.logger.log_info("Target recovered! Continuing fuzzing")
                recovered = True
            except exception.FuzzowskiTargetConnectionFailedError:
                self.logger.log_info("Target still down")
            except Exception as e:
                self.logger.log_info("Target still down")
                self.logger.log_info("Exception {}: {}".format(type(e).__name__, str(e)))
        return recovered

    # --------------------------------------------------------------- #

    def print_requests(self):
        """Prints the Requests of this Test Case as python code"""
        helpers.print_python(self.path)

    def print_poc(self):
        """Prints the Test Case as PoC code that can be run standalone"""
        # TODO: Take all options, send the whole test case instead of parameters
        helpers.print_poc(self.session.target, self.path,
                          self.session.opts.receive_data_after_each_request, self.session.opts.receive_data_after_fuzz)

    def get_poc(self):
        """Gets the code of the PoC of this Test Case that can be run standalone"""
        exploit_code = helpers.get_exploit_code(self.session.target, self.path,
                                                self.session.opts.receive_data_after_each_request,
                                                self.session.opts.receive_data_after_fuzz)
        return exploit_code

    # --------------------------------------------------------------- #

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, self.id)

    def info(self):
        """Returns information about the test case"""
        return f'Test Case {self.id} {"(Disabled)" if self.disabled else ""}\n' \
               f'  Path: {self.path_name}\n' \
               f'  Mutant: {self.mutant_name}\n' \
               f'  Errors: {self.errors}'

    def _callback_current_node(self, node, edge, original=False):
        """Execute callback preceding current node.

        Returns:
            bytes: Data rendered by current node if any; otherwise None.
            :type original: object
        """
        data = None

        # if the edge has a callback, process it. the callback has the option to render the node, modify it and return.
        if edge.callback:
            self.logger.open_test_step('Callback function')
            data = edge.callback(self.session.target, self.logger, session=self, node=node, edge=edge,
                                 original=original)

        return data

    @property
    def disabled(self):
        """Returns if the TestCase is disabled due to the actual request or actual mutant is disabled"""
        try:
            return self.request.disabled or self.request.mutant.disabled
        except AttributeError:
            return False
