import pickle
import itertools
import logging
import os
import re
import time
import traceback
import zlib
import sys
import signal

from prompt_toolkit import HTML, print_formatted_text
from prompt_toolkit.styles import Style, merge_styles

from . import helpers
from . import blocks, constants
from . import event_hook
from . import pgraph
from . import primitives
from . import exception

from .loggers import FuzzLogger, FuzzLoggerText
from .connections import Target
from .prompt import CommandPrompt
from .suspect import Suspect
from .ip_constants import DEFAULT_MAX_RECV
from .restarters import IRestarter
# from .monitors import IMonitor
from .blocks.ifuzzable import IFuzzable


class Connection(pgraph.Edge):
    def __init__(self, src, dst, callback=None):
        """
        Extends pgraph.edge with a callback option. This allows us to register a function to call between node
        transmissions to implement functionality such as challenge response systems. The callback method must follow
        this prototype::

            def callback(target, fuzz_data_logger, session, node, edge, original=False, *args, **kwargs)

        Where node is the node about to be sent, edge is the last edge along the current fuzz path to "node", session
        is a pointer to the session instance which is useful for snagging data such as session.last_recv which contains
        the data returned from the last socket transmission and sock is the live socket. A callback is also useful in
        situations where, for example, the size of the next packet is specified in the first packet.

        Args:
            src (int): Edge source ID
            dst (int): Edge destination ID
            callback (function): Optional. Callback function to pass received data to between node xmits
        """

        super(Connection, self).__init__(src, dst)

        self.callback = callback


class Session(pgraph.Graph, CommandPrompt):
    """
    Implements main fuzzing functionality, contains all configuration parameters, etc.

    Args:
        session_filename (str): Filename to serialize persistent data to. Default None.
        index_start (int);      First test case index to run
        index_end (int);        Last test case index to run
        sleep_time (float):     Time in seconds to sleep in between tests. Default 0.
        restart_interval (int): Restart the target after n test cases, disable by setting to 0 (default).
        crash_threshold_request (int):  Maximum number of crashes allowed before a request is exhausted. Default 12.
        crash_threshold_element (int):  Maximum number of crashes allowed before an element is exhausted. Default 3.
        restart_sleep_time (int): Time in seconds to sleep when target can't be restarted. Default 5.
        fuzz_loggers (list of ifuzz_logger.IFuzzLogger): For saving test data and results.. Default Log to STDOUT.
        receive_data_after_each_request (bool): If True, Session will attempt to receive a reply after transmitting
                                                each non-fuzzed node. Default True.
        check_data_received_each_request (bool): If True, Session will verify that some data has
                                                 been received after transmitting each non-fuzzed node, and if not,
                                                 register a failure. If False, this check will not be performed. Default
                                                 False. A receive attempt is still made unless
                                                 receive_data_after_each_request is False.
        receive_data_after_fuzz (bool): If True, Session will attempt to receive a reply after transmitting
                                        a fuzzed message. Default False.
        ignore_connection_reset (bool): Log ECONNRESET errors ("Target connection reset") as "info" instead of
                                failures.
        ignore_connection_aborted (bool): Log ECONNABORTED errors as "info" instead of failures.
        ignore_connection_issues_when_sending_fuzz_data (bool): Ignore fuzz data transmission failures. Default True.
                                This is usually a helpful setting to enable, as targets may drop connections once a
                                message is clearly invalid.
        target (Target):        Target for fuzz session. Target must be fully initialized. Default None.
        restarter (IRestarter): Restarter module initialized. Will call restart() when the target is down. Default None
        monitors (list of IMonitor): Monitor modules
        new_connection_between_packets: bool = True. Close and Open the connection to the target between packets
        transmit_next_node: bool = False. Transmit the next node of the graph when fuzzing a node
    """

    def __init__(self, session_filename: str = None, index_start: int = 1, index_end: int = None,
                 sleep_time: float = 0.0,
                 restart_interval: float = 0,
                 crash_threshold_request: int = 5,
                 crash_threshold_element: int = 3,
                 restart_sleep_time: float = 5,
                 fuzz_loggers: "list of FuzzLogger" = None,
                 receive_data_after_each_request: bool = True,
                 check_data_received_each_request: bool = False,
                 receive_data_after_fuzz: bool = False,
                 ignore_connection_reset: bool = False,
                 ignore_connection_aborted: bool = False,
                 ignore_connection_issues_when_sending_fuzz_data: bool = True,
                 target: Target = None,
                 restarter: IRestarter = None,
                 monitors: "list of IMonitor" = [],
                 new_connection_between_packets: bool = False,
                 transmit_next_node: bool = False
                 ):
        self._ignore_connection_reset = ignore_connection_reset
        self._ignore_connection_aborted = ignore_connection_aborted
        self._ignore_connection_issues_when_sending_fuzz_data = ignore_connection_issues_when_sending_fuzz_data

        super(Session, self).__init__()
        self.save_crashes = True
        self._index_start = max(index_start, 1)
        self._index_end = index_end
        self.sleep_time = sleep_time
        self.restart_interval = restart_interval
        self._crash_threshold_node = crash_threshold_request
        self._crash_threshold_element = crash_threshold_element
        self.restart_sleep_time = restart_sleep_time
        helpers.mkdir_safe(os.path.join(constants.RESULTS_DIR))

        if fuzz_loggers is None:
            fuzz_loggers = [FuzzLoggerText()]

        # self._run_id = datetime.datetime.utcnow().replace(microsecond=0).isoformat().replace(':', '-')
        # self._db_filename = os.path.join(constants.RESULTS_DIR, 'run-{0}.db'.format(self._run_id))

        if session_filename is not None:
            self.session_filename = os.path.join(constants.RESULTS_DIR, session_filename)
            self.log_filename = os.path.join(constants.RESULTS_DIR, ''.join(session_filename.split('.')[:-1]) + '.log')
            fuzz_loggers.append(FuzzLoggerText(file_handle=open(self.log_filename, 'a')))

        else:
            self.session_filename = None

        self._fuzz_data_logger = FuzzLogger(fuzz_loggers)

        if self.session_filename is not None:
            self._fuzz_data_logger.log_info('Using session file: {}'.format(self.session_filename))

        self._check_data_received_each_request = check_data_received_each_request
        self._receive_data_after_each_request = receive_data_after_each_request
        self._receive_data_after_fuzz = receive_data_after_fuzz
        self._skip_current_node_after_current_test_case = False
        self._skip_current_element_after_current_test_case = False
        self._post_test_case_methods = []

        self.total_num_mutations = 0
        self.total_mutant_index = 0
        self.fuzz_node = None
        self.targets = []

        self.is_paused = False
        self.crashing_primitives = {}
        self.on_failure = event_hook.EventHook()
        self.suspects = []
        self.crashes = []
        self.disabled_elements = []
        # import settings if they exist.
        self.import_file()

        # create a root node. we do this because we need to start fuzzing from a single point and the user may want
        # to specify a number of initial requests.
        self.root = pgraph.Node()
        self.root.name = "__ROOT_NODE__"
        self.root.label = self.root.name
        self.last_recv = None
        self.last_send = None

        self.add_node(self.root)

        if target is not None:
            try:
                self.add_target(target=target)
            except exception.FuzzowskiRpcError as e:
                self._fuzz_data_logger.log_error(str(e))
                raise

        self.is_paused = True
        self._path = None
        self._restarter = restarter

        self.monitors = []
        for monitor_class in monitors:
            self.monitors.append(monitor_class(self))  # TODO: How to pass arbitrary args to monitors? think a good way!
                                                  # TODO: Maybe passing all the args and let the monitor pick them?

        self._new_connection_between_packets = new_connection_between_packets
        self._transmit_next_node = transmit_next_node

        # self.console = CommandPrompt(COMMANDS)
        # Hook ctrl-C signal to go to the Pause Command Prompt
        signal.signal(signal.SIGINT, self._signal_handler)
        # super(Session, self).__init__()

    def add_node(self, node):
        """
        Add a pgraph node to the graph. We overload this routine to automatically generate and assign an ID whenever a
        node is added.

        Args:
            node (pgraph.Node): Node to add to session graph
        """

        node.number = len(self.nodes)
        node.id = len(self.nodes)

        if node.id not in self.nodes:
            self.nodes[node.id] = node

        return self

    def add_target(self, target):
        """
        Add a target to the session. Multiple targets can be added for parallel fuzzing.

        Args:
            target (Target): Target to add to session
        """

        # pass specified target parameters to the PED-RPC server.
        # target.pedrpc_connect()
        target.set_fuzz_data_logger(fuzz_data_logger=self._fuzz_data_logger)

        # add target to internal list.
        self.targets.append(target)

    def connect(self, src, dst=None, callback=None):
        """
        Create a connection between the two requests (nodes) and register an optional callback to process in between
        transmissions of the source and destination request. Leverage this functionality to handle situations such as
        challenge response systems. The session class maintains a top level node that all initial requests must be
        connected to. Example::

            sess = sessions.session()
            sess.connect(sess.root, s_get("HTTP"))

        If given only a single parameter, sess.connect() will default to attaching the supplied node to the root node.
        This is a convenient alias and is identical to the second line from the above example::

            sess.connect(s_get("HTTP"))

        If you register callback method, it must follow this prototype::

            def callback(target, fuzz_data_logger, session, node, edge, *args, **kwargs)

        Where node is the node about to be sent, edge is the last edge along the current fuzz path to "node", session
        is a pointer to the session instance which is useful for snagging data such as session.last_recv which contains
        the data returned from the last socket transmission and sock is the live socket. A callback is also useful in
        situations where, for example, the size of the next packet is specified in the first packet. As another
        example, if you need to fill in the dynamic IP address of the target register a callback that snags the IP
        from sock.getpeername()[0].

        Args:
            src (str or Request (pgrah.Node)): Source request name or request node
            dst (str or Request (pgrah.Node), optional): Destination request name or request node
            callback (def, optional): Callback function to pass received data to between node xmits. Default None.

        Returns:
            pgraph.Edge: The edge between the src and dst.
        """

        # if only a source was provided, then make it the destination and set the source to the root node.
        if dst is None:
            dst = src
            src = self.root

        # if source or destination is a name, resolve the actual node.
        if type(src) is str:
            src = self.find_node("name", src)

        if type(dst) is str:
            dst = self.find_node("name", dst)

        # if source or destination is not in the graph, add it.
        if src != self.root and not self.find_node("name", src.name):
            self.add_node(src)

        if self.find_node("name", dst.name) is None:
            self.add_node(dst)

        # create an edge between the two nodes and add it to the graph.
        edge = Connection(src.id, dst.id, callback)
        self.add_edge(edge)

        return edge

    def export_file(self, session_filename=None):
        """
        Dump various object values to disk.

        @see: import_file()
        """
        if session_filename is None:
            session_filename = self.session_filename

        if not session_filename:
            return

        data = {
            "session_filename": self.session_filename,
            "index_start": self.total_mutant_index,
            "sleep_time": self.sleep_time,
            "restart_sleep_time": self.restart_sleep_time,
            "restart_interval": self.restart_interval,
            "crash_threshold": self._crash_threshold_node,
            "total_num_mutations": self.total_num_mutations,
            "total_mutant_index": self.total_mutant_index,
            "is_paused": self.is_paused,
            "suspects": self.suspects,
            "crashes": self.crashes,
            "disabled_elements": self.disabled_elements
        }

        fh = open(session_filename, "wb+")
        fh.write(zlib.compress(pickle.dumps(data, protocol=2)))
        fh.close()

    def feature_check(self):
        """Check all messages/features.

        Returns:
            None
        """
        self.total_mutant_index = 0
        self.total_num_mutations = self.num_mutations()

        self._message_check(self._iterate_messages())

    def fuzz(self):
        """Fuzz the entire protocol tree.

        Iterates through and fuzzes all fuzz cases, skipping according to
        self.skip and restarting based on self.restart_interval.

        If you want the web server to be available, your program must persist
        after calling this method. helpers.pause_for_signal() is
        available to this end.

        Returns:
            None
        """
        self.total_mutant_index = 0
        self.total_num_mutations = self.num_mutations()

        # Disable elements loaded
        for element_path in self.disabled_elements:
            self._disable_element_by_path(element_path)

        # Start fuzzing!
        self._main_fuzz_loop(self._iterate_protocol())

    def fuzz_single_node_by_path(self, node_names):
        """Fuzz a particular node via the path in node_names.

        Args:
            node_names (list of str): List of node names leading to target.
        """
        node_edges = self._path_names_to_edges(node_names=node_names)

        self.total_mutant_index = 0
        self.total_num_mutations = self.nodes[node_edges[-1].dst].num_mutations()

        self._main_fuzz_loop(self._iterate_single_node(node_edges))

    def fuzz_by_name(self, name):
        """Fuzz a particular test case or node by name.

        Args:
            name (str): Name of node.
        """
        self.fuzz_single_node_by_path(re.split('->', name))

    def fuzz_single_case(self, mutant_index):
        """Fuzz a test case by mutant_index.

        Args:
            mutant_index (int): Positive non-zero integer.

        Returns:
            None

        Raises:
            sex.SulleyRuntimeError: If any error is encountered while executing the test case.
        """
        self.total_mutant_index = 0
        self.total_num_mutations = 1

        self._main_fuzz_loop(self._iterate_single_case_by_index(mutant_index))

    def _message_check(self, fuzz_case_iterator):
        """Check messages for compatibility.

        Preconditions: `self.total_mutant_index` and `self.total_num_mutations` are set properly.

        Args:
            fuzz_case_iterator (Iterable): An iterator that walks through

        Returns:
            None
        """
        # self.server_init()
        pass

        try:
            for fuzz_args in fuzz_case_iterator:
                self._check_message(*fuzz_args)
        # except KeyboardInterrupt:
        #     self.export_file()
        #     self._fuzz_data_logger.log_error("SIGINT received ... exiting")
        #     raise
        except exception.FuzzowskiRestartFailedError:
            self._fuzz_data_logger.log_error("Restarting the target failed, exiting.")
            self.export_file()
            raise
        except exception.FuzzowskiTargetConnectionFailedError:
            # exception should have already been handled but rethrown in order to escape test run
            pass
        except Exception:
            self._fuzz_data_logger.log_error(
                "Unexpected exception! {0}".format(traceback.format_exc()))
            self.export_file()
            raise

    def _main_fuzz_loop(self, fuzz_case_iterator):
        """Execute main fuzz logic; takes an iterator of test cases.

        Preconditions: `self.total_mutant_index` and `self.total_num_mutations` are set properly.

        Args:
            fuzz_case_iterator (Iterable): An iterator that walks through fuzz cases.

        Returns:
            None
        """
        # self.server_init()

        try:
            num_cases_actually_fuzzed = 0
            for fuzz_args in fuzz_case_iterator:
                if self.total_mutant_index < self._index_start:
                    continue
                elif self._index_end is not None and self.total_mutant_index > self._index_end:
                    break
                # Check restart interval
                if num_cases_actually_fuzzed \
                        and self.restart_interval \
                        and num_cases_actually_fuzzed % self.restart_interval == 0:
                    self._fuzz_data_logger.open_test_step("restart interval of %d reached" % self.restart_interval)
                    # self.restart_target(self.targets[0])
                try:
                    self._fuzz_current_case(*fuzz_args)
                except (exception.FuzzowskiTargetConnectionFailedError, OSError):
                    # When the connection fails, we want to pause the fuzzer, save the packets,etc
                    # self.is_paused = True
                    self._wait_until_target_recovered()
                    self.targets[0].open()  # Open a new connection, as the last one will be closed
                    # recovered = False
                    # while not recovered:
                    #     self._fuzz_data_logger.log_info(
                    #         "Target seems down. Sleeping for %d seconds" % self.restart_sleep_time
                    #     )
                    #     time.sleep(self.restart_sleep_time)
                    #     try:
                    #         self._test_normal_current_case(self._path)
                    #         self._fuzz_data_logger.log_info("Target recovered! Continuing fuzzing")
                    #         recovered = True
                    #     except exception.FuzzowskiTargetConnectionFailedError:
                    #         self._fuzz_data_logger.log_info("Target still down")
                    #     except Exception as e:
                    #         self._fuzz_data_logger.log_info("Target still down")
                    #         self._fuzz_data_logger.log_info("Exception {}: {}".format(type(e).__name__, str(e)))

                num_cases_actually_fuzzed += 1
        # except KeyboardInterrupt:
        #     # TODO: should wait for the end of the ongoing test case
        #     self.export_file()
        #     self._fuzz_data_logger.log_error("SIGINT received ... exiting")
        #     raise
        except exception.FuzzowskiRestartFailedError:
            self._fuzz_data_logger.log_error("Restarting the target failed, exiting.")
            self.export_file()
            raise
        except exception.FuzzowskiTargetConnectionFailedError:
            # exception should have already been handled but rethrown in order to escape test run
            pass
        except Exception:
            self._fuzz_data_logger.log_error(
                "Unexpected exception! {0}".format(traceback.format_exc()))
            self.export_file()
            raise

    def import_file(self, session_filename=None):
        """
        Load various object values from disk.

        @see: export_file()
        """

        if session_filename is None:
            session_filename = self.session_filename

        if session_filename is None:
            return

        try:
            with open(session_filename, "rb") as f:
                data = pickle.loads(zlib.decompress(f.read()))
        except (IOError, zlib.error, pickle.UnpicklingError):
            return

        # update the skip variable to pick up fuzzing from last test case.
        self._index_start = data["total_mutant_index"]
        self.session_filename = data["session_filename"]
        self.sleep_time = data["sleep_time"]
        self.restart_sleep_time = data["restart_sleep_time"]
        self.restart_interval = data["restart_interval"]
        self._crash_threshold_node = data["crash_threshold"]
        self.total_num_mutations = data["total_num_mutations"]
        self.total_mutant_index = data["total_mutant_index"]
        self.is_paused = data["is_paused"]
        self.suspects = data["suspects"]
        self.crashes = data["crashes"]
        self.disabled_elements = data["disabled_elements"]

    def num_mutations(self, this_node=None, path=()):
        """
        Number of total mutations in the graph. The logic of this routine is identical to that of fuzz(). See fuzz()
        for inline comments. The member variable self.total_num_mutations is updated appropriately by this routine.

        Args:
            this_node (request (node)): Current node that is being fuzzed. Default None.
            path (list): Nodes along the path to the current one being fuzzed. Default [].

        Returns:
            int: Total number of mutations in this session.
        """

        if this_node is None:
            this_node = self.root
            self.total_num_mutations = 0

        if isinstance(path, tuple):
            path = list(path)

        for edge in self.edges_from(this_node.id):
            next_node = self.nodes[edge.dst]
            self.total_num_mutations += next_node.num_mutations()

            if edge.src != self.root.id:
                path.append(edge)

            self.num_mutations(next_node, path)

        # finished with the last node on the path, pop it off the path stack.
        if path:
            path.pop()

        return self.total_num_mutations

    def _pause_if_pause_flag_is_set(self):
        """
        If that pause flag is raised, enter an endless loop until it is lowered.
        """
        # while 1:
        #     if self.is_paused:
        #         time.sleep(1)
        #     else:
        #         break
        if self.is_paused:
            self.start_prompt()
            self.is_paused = False

    def _check_for_passively_detected_failures(self, target):
        """Check for and log passively detected failures. Return True if any found.

        Returns:
            bool: True if failures were found. False otherwise.
        """
        pass
        # TODO: Check IThreadedMonitors

    def _process_failures(self, target):
        """Process any failures in self.crash_synopses.

        If self.crash_synopses contains any entries, perform these failure-related actions:
         - log failure summary if needed
         - exhaust node if crash threshold is reached
         - target restart

        Should be called after each fuzz test case.

        Args:
            target (Target): Target to restart if failure occurred.

        Returns:
            bool: True if any failures were found; False otherwise.
        """
        crash_synopses = self._fuzz_data_logger.failed_test_cases.get(self._fuzz_data_logger.all_test_cases[-1], [])
        if len(crash_synopses) > 0:
            self._fuzz_data_logger.open_test_step("Failure summary")

            # retrieve the primitive that caused the crash and increment it's individual crash count.
            # self.crashing_primitives[self.fuzz_node.mutant] = self.crashing_primitives.get(self.fuzz_node.mutant, 0) + 1
            # self.crashing_primitives[self.fuzz_node] = self.crashing_primitives.get(self.fuzz_node, 0) + 1

            # print crash synopsis
            if len(crash_synopses) > 1:
                # Prepend a header if > 1 failure report, so that they are visible from the main web page
                synopsis = "({0} reports) {1}".format(len(crash_synopses), "\n".join(crash_synopses))
            else:
                synopsis = "\n".join(crash_synopses)
            self._fuzz_data_logger.log_info(synopsis)

            # TODO: FIX
            # if self.fuzz_node.mutant is not None and \
            #         self.crashing_primitives[self.fuzz_node] >= self._crash_threshold_node:
            #     skipped = self.fuzz_node.num_mutations() - self.fuzz_node.mutant_index
            #     self._skip_current_node_after_current_test_case = True
            #     self._fuzz_data_logger.open_test_step(
            #         "Crash threshold reached for this request, exhausting {0} mutants.".format(skipped))
            #     self.total_mutant_index += skipped
            #     self.fuzz_node.mutant_index += skipped
            # elif self.fuzz_node.mutant is not None and \
            #         self.crashing_primitives[self.fuzz_node.mutant] >= self._crash_threshold_element:
            #     if not isinstance(self.fuzz_node.mutant, primitives.Group) \
            #             and not isinstance(self.fuzz_node.mutant, blocks.Repeat):
            #         skipped = self.fuzz_node.mutant.num_mutations() - self.fuzz_node.mutant.mutant_index
            #         self._skip_current_element_after_current_test_case = True
            #         self._fuzz_data_logger.open_test_step(
            #             "Crash threshold reached for this element, exhausting {0} mutants.".format(skipped))
            #         self.total_mutant_index += skipped
            #         self.fuzz_node.mutant_index += skipped

            # if self.fuzz_node.mutant is not None and \
            #         self.crashing_primitives[self.fuzz_node] >= self._crash_threshold_node:
            #     self.fuzz_node.disabled = True
            #     self._fuzz_data_logger.open_test_step(
            #         "Crash threshold reached for this request, exhausting node {}.".format(self.fuzz_node.name))
            # elif self.fuzz_node.mutant is not None and \
            #         self.crashing_primitives[self.fuzz_node.mutant] >= self._crash_threshold_element:
            #     if not isinstance(self.fuzz_node.mutant, primitives.Group) \
            #             and not isinstance(self.fuzz_node.mutant, blocks.Repeat):
            #         self._disable_current_element()
            #         node_name = self._test_case_name(self._path, self.fuzz_node.mutant)
            #         self._fuzz_data_logger.open_test_step(
            #             "Crash threshold reached for this element, exhausting mutant {}.".format(node_name)
            #         )

            # TODO: Check if restart_target defined, and execute it!
            # self.restart_target(target)
            return True
        else:
            return False

    def register_post_test_case_callback(self, method):
        """Register a post- test case method.

        The registered method will be called after each fuzz test case.

        Potential uses:
         * Closing down a connection.
         * Checking for expected responses.

        The order of callback events is as follows::

            pre_send() - req - callback ... req - callback - post-test-case-callback

        Args:
            method (function): A method with the same parameters as :func:`~Session.post_send`
            """
        self._post_test_case_methods.append(method)

    # noinspection PyUnusedLocal
    def example_test_case_callback(self, target, fuzz_data_logger, session, *args, **kwargs):
        """
        Example call signature for methods given to :func:`~Session.register_post_test_case_callback`.

        Args:
            target (Target): Target with sock-like interface.
            fuzz_data_logger (ifuzz_logger.IFuzzLogger): Allows logging of test checks and passes/failures.
                Provided with a test case and test step already opened.

            session (Session): Session object calling post_send.
                Useful properties include last_send and last_recv.

            sock: DEPRECATED Included for backward-compatibility. Same as target.
            args: Implementations should include \*args and \**kwargs for forward-compatibility.
            kwargs: Implementations should include \*args and \**kwargs for forward-compatibility.
        """
        # default to doing nothing.
        self._fuzz_data_logger.log_info("No post_send callback registered.")

    # noinspection PyMethodMayBeStatic
    def pre_send(self, sock):
        """
        Overload or replace this routine to specify actions to run prior to each fuzz request. The order of events is
        as follows::

            pre_send() - req - callback ... req - callback - post_send()

        When fuzzing RPC for example, register this method to establish the RPC bind.

        @see: pre_send()

        Args:
            sock (Socket): Connected socket to target
        """

        # default to doing nothing.
        pass

    def _callback_current_node(self, node, edge, original=False):
        """Execute callback preceding current node.

        Returns:
            bytes: Data rendered by current node if any; otherwise None.
            :type original: object
        """
        data = None

        # if the edge has a callback, process it. the callback has the option to render the node, modify it and return.
        if edge.callback:
            self._fuzz_data_logger.open_test_step('Callback function')
            data = edge.callback(self.targets[0], self._fuzz_data_logger, session=self, node=node, edge=edge, original=original)

        return data

    def transmit_normal(self, sock, node, edge, callback_data):
        """Render and transmit a non-fuzzed node, process callbacks accordingly.

        Args:
            sock (Target, optional): Socket-like object on which to transmit node
            node (pgraph.node.node (Node), optional): Request/Node to transmit
            edge (pgraph.edge.edge (pgraph.edge), optional): Edge along the current fuzz path from "node" to next node.
            callback_data (bytes): Data from previous callback.
        """
        if callback_data:
            data = callback_data
        else:
            data = node.render()

        try:  # send
            self.targets[0].send(data)
            self.last_send = data
        except exception.FuzzowskiTargetConnectionReset as e:
            # TODO: Switch _ignore_connection_reset for _ignore_transmission_error, or provide retry mechanism
            if self._ignore_connection_reset:
                self._fuzz_data_logger.log_info(constants.ERR_CONN_RESET)
            else:
                self._fuzz_data_logger.log_fail(constants.ERR_CONN_RESET)
                self._save_actual_case_as_suspect(e)
        except exception.FuzzowskiTargetConnectionAborted as e:
            # TODO: Switch _ignore_connection_aborted for _ignore_transmission_error, or provide retry mechanism
            msg = constants.ERR_CONN_ABORTED.format(socket_errno=e.socket_errno,
                                                    socket_errmsg=e.socket_errmsg)
            if self._ignore_connection_aborted:
                self._fuzz_data_logger.log_info(msg)
            else:
                self._fuzz_data_logger.log_fail(msg)
                self._save_actual_case_as_suspect(e)
        try:  # recv
            if self._receive_data_after_each_request:
                # self.last_recv = self.targets[0].recv(DEFAULT_MAX_RECV)
                self.last_recv = self.targets[0].recv_all(DEFAULT_MAX_RECV)

                if self._check_data_received_each_request:
                    self._fuzz_data_logger.log_check("Verify some data was received from the target.")
                    if not self.last_recv:
                        # Assume a crash?
                        self._fuzz_data_logger.log_fail("Nothing received from target.")
                        self._save_actual_case_as_suspect(e)
                    else:
                        self._fuzz_data_logger.log_pass("Some data received from target.")
        except exception.FuzzowskiTargetRecvTimeout as e:
            self.last_recv = b''
            if self._check_data_received_each_request:
                self._fuzz_data_logger.log_check("Verify some data was received from the target.")
                if not self.last_recv:
                    # Assume a crash?
                    self._fuzz_data_logger.log_fail("Nothing received from target.")
                    self._save_actual_case_as_suspect(e)
                else:
                    self._fuzz_data_logger.log_pass("Some data received from target.")
        except exception.FuzzowskiTargetConnectionReset as e:
            if self._check_data_received_each_request:
                self._fuzz_data_logger.log_fail(constants.ERR_CONN_RESET)
                self._save_actual_case_as_suspect(e)
            else:
                self._fuzz_data_logger.log_info(constants.ERR_CONN_RESET)
        except exception.FuzzowskiTargetConnectionAborted as e:
            msg = constants.ERR_CONN_ABORTED.format(socket_errno=e.socket_errno,
                                                    socket_errmsg=e.socket_errmsg)
            if self._check_data_received_each_request:
                self._fuzz_data_logger.log_fail(msg)
                self._save_actual_case_as_suspect(e)
            else:
                self._fuzz_data_logger.log_info(msg)

    def transmit_fuzz(self, sock, node, edge, callback_data):
        """Render and transmit a fuzzed node, process callbacks accordingly.

        Args:
            sock (Target, optional): Socket-like object on which to transmit node
            node (pgraph.node.node (Node), optional): Request/Node to transmit
            edge (pgraph.edge.edge (pgraph.edge), optional): Edge along the current fuzz path from "node" to next node.
            callback_data (bytes): Data from previous callback.
        """
        if callback_data:
            data = callback_data
        else:
            data = node.render()

        try:  # send
            self.targets[0].send(data)
            self.last_send = data
        except exception.FuzzowskiTargetConnectionReset as e:
            if self._ignore_connection_issues_when_sending_fuzz_data:
                self._fuzz_data_logger.log_info(constants.ERR_CONN_RESET)
            else:
                self._fuzz_data_logger.log_fail(constants.ERR_CONN_RESET)
                self._save_actual_case_as_suspect(e)
        except exception.FuzzowskiTargetConnectionAborted as e:
            msg = constants.ERR_CONN_ABORTED.format(socket_errno=e.socket_errno,
                                                    socket_errmsg=e.socket_errmsg)
            if self._ignore_connection_issues_when_sending_fuzz_data:
                self._fuzz_data_logger.log_info(msg)
            else:
                self._fuzz_data_logger.log_fail(msg)
                self._save_actual_case_as_suspect(e)

        try:  # recv
            if self._receive_data_after_fuzz:
                # self.last_recv = self.targets[0].recv(DEFAULT_MAX_RECV)
                self.last_recv = self.targets[0].recv_all(DEFAULT_MAX_RECV)

        except exception.FuzzowskiTargetRecvTimeout as e:
            if self._check_data_received_each_request:
                self._fuzz_data_logger.log_check("Verify some data was received from the target.")
                if not self.last_recv:
                    # Assume a crash?
                    self._fuzz_data_logger.log_fail("Nothing received from target.")
                    self._save_actual_case_as_suspect(e)
                else:
                    self._fuzz_data_logger.log_pass("Some data received from target.")
        except exception.FuzzowskiTargetConnectionReset as e:
            if self._check_data_received_each_request:
                self._fuzz_data_logger.log_fail(constants.ERR_CONN_RESET)
                self._save_actual_case_as_suspect(e)
            else:
                self._fuzz_data_logger.log_info(constants.ERR_CONN_RESET)
        except exception.FuzzowskiTargetConnectionAborted as e:
            msg = constants.ERR_CONN_ABORTED.format(socket_errno=e.socket_errno,
                                                    socket_errmsg=e.socket_errmsg)
            if self._check_data_received_each_request:
                self._fuzz_data_logger.log_fail(msg)
                self._save_actual_case_as_suspect(e)
            else:
                self._fuzz_data_logger.log_info(msg)
            pass


    def transmit_original(self, sock, node, edge, callback_data):
        """Render and transmit an original, process callbacks accordingly.

        Args:
            sock (Target, optional): Socket-like object on which to transmit node
            node (pgraph.node.node (Node), optional): Request/Node to transmit
            edge (pgraph.edge.edge (pgraph.edge), optional): Edge along the current fuzz path from "node" to next node.
            callback_data (bytes): Data from previous callback.
        """
        if callback_data:
            data = callback_data
        else:
            data = node.original_value
            # data = node.render()

        try:  # send
            self.targets[0].send(data)
            self.last_send = data
        except exception.FuzzowskiTargetConnectionReset as e:
            # TODO: Switch _ignore_connection_reset for _ignore_transmission_error, or provide retry mechanism
            if self._ignore_connection_reset:
                self._fuzz_data_logger.log_info(constants.ERR_CONN_RESET)
            else:
                self._fuzz_data_logger.log_fail(constants.ERR_CONN_RESET)
                # self._save_actual_case_as_suspect(e)
        except exception.FuzzowskiTargetConnectionAborted as e:
            # TODO: Switch _ignore_connection_aborted for _ignore_transmission_error, or provide retry mechanism
            msg = constants.ERR_CONN_ABORTED.format(socket_errno=e.socket_errno,
                                                    socket_errmsg=e.socket_errmsg)
            if self._ignore_connection_aborted:
                self._fuzz_data_logger.log_info(msg)
            else:
                self._fuzz_data_logger.log_fail(msg)
                # self._save_actual_case_as_suspect(e)
        try:  # recv
            if self._receive_data_after_each_request:
                # self.last_recv = self.targets[0].recv(DEFAULT_MAX_RECV)
                self.last_recv = self.targets[0].recv_all(DEFAULT_MAX_RECV)

                if self._check_data_received_each_request:
                    self._fuzz_data_logger.log_check("Verify some data was received from the target.")
                    if not self.last_recv:
                        # Assume a crash?
                        self._fuzz_data_logger.log_fail("Nothing received from target.")
                        # self._save_actual_case_as_suspect(e)
                    else:
                        self._fuzz_data_logger.log_pass("Some data received from target.")
        except exception.FuzzowskiTargetRecvTimeout as e:
            self.last_recv = b''
            if self._check_data_received_each_request:
                self._fuzz_data_logger.log_check("Verify some data was received from the target.")
                if not self.last_recv:
                    # Assume a crash?
                    self._fuzz_data_logger.log_fail("Nothing received from target.")
                    # self._save_actual_case_as_suspect(e)
                else:
                    self._fuzz_data_logger.log_pass("Some data received from target.")
        except exception.FuzzowskiTargetConnectionReset as e:
            if self._check_data_received_each_request:
                self._fuzz_data_logger.log_fail(constants.ERR_CONN_RESET)
                # self._save_actual_case_as_suspect(e)
            else:
                self._fuzz_data_logger.log_info(constants.ERR_CONN_RESET)
        except exception.FuzzowskiTargetConnectionAborted as e:
            msg = constants.ERR_CONN_ABORTED.format(socket_errno=e.socket_errno,
                                                    socket_errmsg=e.socket_errmsg)
            if self._check_data_received_each_request:
                self._fuzz_data_logger.log_fail(msg)
                # self._save_actual_case_as_suspect(e)
            else:
                self._fuzz_data_logger.log_info(msg)

    # def build_webapp_thread(self, port=constants.DEFAULT_WEB_UI_PORT):
    #     app.session = self
    #     http_server = HTTPServer(WSGIContainer(app))
    #     http_server.listen(port)
    #     flask_thread = threading.Thread(target=IOLoop.instance().start)
    #     flask_thread.daemon = True
    #     return flask_thread

    def _iterate_messages(self):
        """Iterates over each message without mutations.

        :raise sex.FuzzowskiRuntimeError:
        """
        if not self.targets:
            raise exception.FuzzowskiRuntimeError("No targets specified in session")

        if not self.edges_from(self.root.id):
            raise exception.FuzzowskiRuntimeError("No requests specified in session")

        self._reset_fuzz_state()

        for x in self._iterate_messages_recursive(this_node=self.root, path=[]):
            yield x

    def _iterate_messages_recursive(self, this_node, path):
        """Recursively iterates over messages. Used by _iterate_messages.

        Args:
            this_node (node.Node): Current node that is being fuzzed.
            path (list of Connection): List of edges along the path to the current one being fuzzed.

        :raise sex.FuzzowskiRuntimeError:
        """
        # step through every edge from the current node.
        for edge in self.edges_from(this_node.id):
            # keep track of the path as we walk through it
            # we keep track of edges as opposed to nodes because if there is more then one path through a set of
            # given nodes we don't want any ambiguity.
            path.append(edge)

            message_path = "->".join([self.nodes[e.dst].name for e in path])
            logging.debug('checking: {0}'.format(message_path))

            self.fuzz_node = self.nodes[path[-1].dst]
            self._path = path
            self.total_mutant_index += 1
            yield (path,)

            for x in self._iterate_messages_recursive(self.fuzz_node, path):
                yield x

        # finished with the last node on the path, pop it off the path stack.
        if path:
            path.pop()

    def _iterate_protocol(self):
        """
        Iterates over fuzz cases and mutates appropriately.
        On each iteration, one may call fuzz_current_case to do the
        actual fuzzing.

        :raise sex.FuzzowskiRuntimeError:
        """
        # we can't fuzz if we don't have at least one target and one request.
        if not self.targets:
            raise exception.FuzzowskiRuntimeError("No targets specified in session")

        if not self.edges_from(self.root.id):
            raise exception.FuzzowskiRuntimeError("No requests specified in session")

        self._reset_fuzz_state()

        for x in self._iterate_protocol_recursive(this_node=self.root, path=[]):
            yield x

    def _iterate_protocol_recursive(self, this_node, path):
        """
        Recursively iterates over fuzz nodes. Used by _fuzz_case_iterator.

        Args:
            this_node (node.Node): Current node that is being fuzzed.
            path (list of Connection): List of edges along the path to the current one being fuzzed.

        :raise sex.FuzzowskiRuntimeError:
        """
        # step through every edge from the current node.
        for edge in self.edges_from(this_node.id):
            # keep track of the path as we fuzz through it, don't count the root node.
            # we keep track of edges as opposed to nodes because if there is more then one path through a set of
            # given nodes we don't want any ambiguity.
            path.append(edge)
            # self._path = path

            message_path = "->".join([self.nodes[e.dst].name for e in path])
            logging.debug('fuzzing: {0}'.format(message_path))

            for x in self._iterate_single_node(path):
                yield x

            # recursively fuzz the remainder of the nodes in the session graph.
            for x in self._iterate_protocol_recursive(self.fuzz_node, path):
                yield x

        # finished with the last node on the path, pop it off the path stack.
        if path:
            path.pop()

    def _iterate_single_node(self, path):
        """Iterate fuzz cases for the last node in path.

        Args:
            path (list of Connection): Nodes along the path to the current one being fuzzed.

        Raises:
            sex.FuzzowskiRuntimeError:
        """
        self.fuzz_node = self.nodes[path[-1].dst]
        self._path = path
        # Loop through and yield all possible mutations of the fuzz node.
        # Note: when mutate() returns False, the node has been reverted to the default (valid) state.
        while self.fuzz_node.mutate():
            self.total_mutant_index += 1
            yield (path,)

            if self._skip_current_node_after_current_test_case:
                self._skip_current_node_after_current_test_case = False
                break
            elif self._skip_current_element_after_current_test_case:
                self._skip_current_element_after_current_test_case = False
                self.fuzz_node.skip_element()
        self.fuzz_node.reset()

    def _iterate_single_case_by_index(self, test_case_index):
        fuzz_index = 1
        for fuzz_args in self._iterate_protocol():
            if fuzz_index >= test_case_index:
                # self.total_mutant_index = 1
                self.total_mutant_index = fuzz_index
                yield fuzz_args
                break
            fuzz_index += 1

    def _path_names_to_edges(self, node_names):
        """Take a list of node names and return a list of edges describing that path.

        Args:
            node_names (list of str): List of node names describing a path.

        Returns:
            list of Connection: List of edges describing the path in node_names.
        """
        cur_node = self.root
        edge_path = []
        for node_name in node_names:
            next_node = None
            for edge in self.edges_from(cur_node.id):
                if self.nodes[edge.dst].name == node_name:
                    edge_path.append(edge)
                    next_node = self.nodes[edge.dst]
                    break
            if next_node is None:
                raise Exception("No edge found from {0} to {1}".format(cur_node.name, node_name))
            else:
                cur_node = next_node
        return edge_path

    def _check_message(self, path):
        """Sends the current message without fuzzing.

        Current test case is controlled by fuzz_case_iterator().

        Args:
            path(list of Connection): Path to take to get to the target node.

        """
        target = self.targets[0]

        self._pause_if_pause_flag_is_set()

        test_case_name = self._test_case_name_feature_check(path)

        self._fuzz_data_logger.open_test_case(
            "{0}: {1}".format(self.total_mutant_index, test_case_name),
            name=test_case_name, index=self.total_mutant_index)

        try:
            try:
                target.open()
            except exception.FuzzowskiTargetConnectionFailedError:
                self._fuzz_data_logger.log_error(constants.ERR_CONN_FAILED_TERMINAL)
                raise

            self.pre_send(target)

            for e in path[:-1]:
                node = self.nodes[e.dst]
                self._fuzz_data_logger.open_test_step("Prep Node '{0}'".format(node.name))
                callback_data = self._callback_current_node(node=node, edge=e)
                self.transmit_normal(target, node, e, callback_data=callback_data)

            callback_data = self._callback_current_node(node=self.fuzz_node, edge=path[-1])

            self._fuzz_data_logger.open_test_step("Node Under Test '{0}'".format(self.fuzz_node.name))
            self.transmit_normal(target, self.fuzz_node, path[-1], callback_data=callback_data)
            target.close()

            self._post_send(target)

            self._fuzz_data_logger.open_test_step("Sleep between tests.")
            self._fuzz_data_logger.log_info("sleeping for %f seconds" % self.sleep_time)
            time.sleep(self.sleep_time)
        finally:
            self.export_file()

    # --------------------------------------------------------------- #

    def _fuzz_current_case(self, path):
        """
        Fuzzes the current test case. Current test case is controlled by
        fuzz_case_iterator().

        Args:
            path(list of Connection): Path to take to get to the target node.

        """
        target = self.targets[0]

        self._pause_if_pause_flag_is_set()

        if self.fuzz_node.mutant.disabled:
            # Do not test disabled node. Skip it!
            return

        test_case_name = self._test_case_name(path, self.fuzz_node.mutant)

        self._fuzz_data_logger.open_test_case("{0}: {1}".format(self.total_mutant_index, test_case_name),
                                              name=test_case_name, index=self.total_mutant_index)

        self._fuzz_data_logger.log_info(
            "Type: %s. Default value: %s. Case %d of %d overall." % (
                type(self.fuzz_node.mutant).__name__,
                repr(self.fuzz_node.mutant.original_value),
                self.total_mutant_index,
                self.total_num_mutations))


        try:
            # try:
            #     target.open()
            # except (exception.FuzzowskiTargetConnectionFailedError, Exception) as e:
            #     try:
            #         self._fuzz_data_logger.log_fail(constants.ERR_CONN_FAILED_RETRY)
            #         target.open()  # Second try, just in case we have a network error not caused by
            #     except (exception.FuzzowskiTargetConnectionFailedError, Exception) as e:
            #         self._fuzz_data_logger.log_error(constants.ERR_CONN_FAILED)
            #         self._save_last_case_as_suspect(e)
            #         # raise
            #         self._restart_target()  # Restart the target if a restarter was set
            #         self._wait_until_target_recovered()  # Wait for target to recover
            #         self._fuzz_current_case(self._path)  # Fuzz again this case, and return!
            #         return
            self._open_fuzzing_target()

            self.pre_send(target)

            for e in path[:-1]:
                node = self.nodes[e.dst]
                callback_data = self._callback_current_node(node=node, edge=e)
                self._fuzz_data_logger.open_test_step("Transmit Prep Node '{0}'".format(node.name))
                self.transmit_normal(target, node, e, callback_data=callback_data)
                # Close and open a new connection to the target if specified by argument
                if self._new_connection_between_packets:
                    target.close()
                    self._open_fuzzing_target()

            callback_data = self._callback_current_node(node=self.fuzz_node, edge=path[-1])
            self._fuzz_data_logger.open_test_step("Fuzzing Node '{0}'".format(self.fuzz_node.name))
            self.transmit_fuzz(target, self.fuzz_node, path[-1], callback_data=callback_data)

            if self._transmit_next_node:

                if self._new_connection_between_packets:
                    target.close()
                    target.open()

                edge = self._get_edge(self.fuzz_node)
                next_node = self.nodes[edge.dst]
                self._fuzz_data_logger.open_test_step("Transmitting Next Node '{0}'".format(next_node.name))
                if next_node is not None:
                    callback_data = self._callback_current_node(node=next_node, edge=edge, original=False)
                    self.transmit_normal(target, next_node, path[-1], callback_data=callback_data)

            target.close()

            # Check monitors
            for monitor in self.monitors:
                monitor_success = monitor.run()
                if not monitor_success:   # TODO: Move the create suspects to the monitor itself?
                    self._save_actual_case_as_suspect(None)

            if not self._check_for_passively_detected_failures(target=target):
                self._post_send(target)
            if self.sleep_time > 0:
                self._fuzz_data_logger.open_test_step("Sleep between tests.")
                self._fuzz_data_logger.log_info("sleeping for %f seconds" % self.sleep_time)
                time.sleep(self.sleep_time)
        finally:
            self._process_failures(target=target)
            self.export_file()

    # --------------------------------------------------------------- #

    def _test_normal_current_case(self, path):
        """
        Sends the current test case without fuzzing. Current test case is controlled by
        fuzz_case_iterator().

        Args:
            path(list of Connection): Path to take to get to the target node.

        """
        target = self.targets[0]

        self._pause_if_pause_flag_is_set()

        test_case_name = self._test_case_name(path, self.fuzz_node.mutant)

        self._fuzz_data_logger.open_test_case("Non Fuzzed {0}: {1}".format(self.total_mutant_index, test_case_name),
                                              name=test_case_name, index=self.total_mutant_index)

        # self._fuzz_data_logger.log_info(
        #     "Type: %s. Default value: %s. Case %d of %d overall." % (
        #         type(self.fuzz_node.mutant).__name__,
        #         repr(self.fuzz_node.mutant.original_value),
        #         self.total_mutant_index,
        #         self.total_num_mutations))


        try:
            try:
                target.open()
            except (exception.FuzzowskiTargetConnectionFailedError, Exception) as e:
                self._fuzz_data_logger.log_fail("Cannot connect to target.")
                raise

            self.pre_send(target)

            for e in path[:-1]:
                node = self.nodes[e.dst]
                callback_data = self._callback_current_node(node=node, edge=e, original=True)
                self._fuzz_data_logger.open_test_step("Transmit Prep Node '{0}'".format(node.name))
                self.transmit_original(target, node, e, callback_data=callback_data)

                if self._new_connection_between_packets:
                    target.close()
                    target.open()

            callback_data = self._callback_current_node(node=self.fuzz_node, edge=path[-1], original=True)
            self._fuzz_data_logger.open_test_step("Transmit Node '{0}'".format(self.fuzz_node.name))
            self.transmit_original(target, self.fuzz_node, path[-1], callback_data=callback_data)

            if self._transmit_next_node:

                if self._new_connection_between_packets:
                    target.close()
                    target.open()

                self._fuzz_data_logger.open_test_step("Transmitting Next Node")
                edge = self._get_edge(self.fuzz_node)
                next_node = self.nodes[edge.dst]
                if next_node is not None:
                    callback_data = self._callback_current_node(node=next_node, edge=edge, original=True)
                    self.transmit_original(target, next_node, path[-1], callback_data=callback_data)

            target.close()

            if not self._check_for_passively_detected_failures(target=target):
                self._post_send(target)

            self._fuzz_data_logger.open_test_step("Sleep between tests.")
            self._fuzz_data_logger.log_info("sleeping for %f seconds" % self.sleep_time)
            time.sleep(self.sleep_time)
        finally:
            #self._process_failures(target=target)
            pass
            #self.export_file()

    # --------------------------------------------------------------- #

    def _get_node_id(self, node: IFuzzable) -> int:
        for i in self.nodes:
            if self.nodes[i] == node:
                return i

    def _get_edge(self, node: IFuzzable):
        node_id = self._get_node_id(node)
        connection_list = self.edges_from(node_id)
        if len(connection_list) > 0:
            edge = connection_list[0]
            return edge

    # --------------------------------------------------------------- #

    def _open_fuzzing_target(self):
        """
        Try to open the target, twice in case one fails, saving last case as suspect if something goes wrong,
        restarting the target if a restarter is defined, and waiting for the target to wake up after that.
        :return:
        """
        target = self.targets[0]
        try:
            target.open()
        except (exception.FuzzowskiTargetConnectionFailedError, Exception) as e:
            try:
                self._fuzz_data_logger.log_fail(constants.ERR_CONN_FAILED_RETRY)
                target.open()  # Second try, just in case we have a network error not caused by
                #print("############################################# TARGET OPEN!")
            except (exception.FuzzowskiTargetConnectionFailedError, Exception) as e:
                self._fuzz_data_logger.log_error(constants.ERR_CONN_FAILED)
                self._save_last_case_as_suspect(e)
                # raise
                self._restart_target()  # Restart the target if a restarter was set
                self._wait_until_target_recovered()  # Wait for target to recover
                # target.open()  # Open a new connection, as the last one will be closed
                self._fuzz_current_case(self._path)  # Fuzz again this case, and return!
                return

    # --------------------------------------------------------------- #

    def _restart_target(self):
        """ It will call the restart() command of the IRestarter instance, if a restarter module was set"""
        if self._restarter is not None:
            try:
                self._fuzz_data_logger.open_test_step('Restarting Target')
                restarter_info = self._restarter.restart()
                self._fuzz_data_logger.log_info(restarter_info)
            except Exception as e:
                self._fuzz_data_logger.log_fail(
                    "The Restarter module {} threw an exception: {}".format(self._restarter.name(), e))

    # --------------------------------------------------------------- #

    def _wait_until_target_recovered(self):
        # When the connection fails, we want to pause the fuzzer, save the packets,etc
        # self.is_paused = True
        recovered = False
        self._fuzz_data_logger.open_test_step('Waiting for target recovery')
        while not recovered:
            self._fuzz_data_logger.log_info(
                "Target seems down. Sleeping for %d seconds" % self.restart_sleep_time
            )
            time.sleep(self.restart_sleep_time)
            try:
                self._test_normal_current_case(self._path)
                self._fuzz_data_logger.log_info("Target recovered! Continuing fuzzing")
                recovered = True
            except exception.FuzzowskiTargetConnectionFailedError:
                self._fuzz_data_logger.log_info("Target still down")
            except Exception as e:
                self._fuzz_data_logger.log_info("Target still down")
                self._fuzz_data_logger.log_info("Exception {}: {}".format(type(e).__name__, str(e)))

    # --------------------------------------------------------------- #

    def _test_case_name_feature_check(self, path):
        message_path = "->".join([self.nodes[e.dst].name for e in path])
        return "FEATURE-CHECK->{0}".format(message_path)

    # --------------------------------------------------------------- #

    def _test_case_name(self, path, mutated_element):
        message_path = "->".join([self.nodes[e.dst].name for e in path])
        if mutated_element.name:
            primitive_under_test = mutated_element.name
        else:
            primitive_under_test = 'no-name'
        return "{0}.{1}.{2}".format(message_path, primitive_under_test, self.fuzz_node.mutant_index)

    # --------------------------------------------------------------- #

    def _post_send(self, target):
        try:
            deprecated_callbacks = [self.post_send]
        except AttributeError:
            deprecated_callbacks = []
        if len(self._post_test_case_methods) + len(deprecated_callbacks) > 0:
            try:
                for f in itertools.chain(self._post_test_case_methods, deprecated_callbacks):
                    self._fuzz_data_logger.open_test_step('Post- test case callback: "{0}"'.format(f.__name__))
                    f(target=target, fuzz_data_logger=self._fuzz_data_logger, session=self, sock=target)
            except exception.FuzzowskiTargetConnectionReset:
                self._fuzz_data_logger.log_fail(constants.ERR_CONN_RESET_FAIL)
            except exception.FuzzowskiTargetConnectionAborted as e:
                self._fuzz_data_logger.log_info(constants.ERR_CONN_ABORTED.format(socket_errno=e.socket_errno,
                                                                                  socket_errmsg=e.socket_errmsg))
                pass
            except exception.FuzzowskiTargetConnectionFailedError:
                self._fuzz_data_logger.log_fail(constants.ERR_CONN_FAILED)
            except Exception:
                self._fuzz_data_logger.log_fail(
                    "Custom post_send method raised uncaught Exception." + traceback.format_exc())
            finally:
                # self._fuzz_data_logger.opl
                pass

    # --------------------------------------------------------------- #

    def _reset_fuzz_state(self):
        """
        Restart the object's fuzz state.

        :return: None
        """
        self.total_mutant_index = 0
        if self.fuzz_node:
            self.fuzz_node.reset()
        self._path = None

    # --------------------------------------------------------------- #

    def _signal_handler(self, _signal, frame):
        self.is_paused = True
        try:
            print_formatted_text(HTML(' <testn>SIGINT received. Pausing fuzzing after this test case...</testn>'),
                                 style=self.get_style())
        except RuntimeError:
            # prints are not safe in signal handlers.
            # This happens if the signal is catch while printing
            pass

    # --------------------------------------------------------------- #

    def _save_last_case_as_suspect(self, exc: exception.FuzzowskiError) -> Suspect:
        total_mutant_index = self.total_mutant_index
        self._go_to_test_case(total_mutant_index - 1)
        suspect = self._save_actual_case_as_suspect(exc)
        self._go_to_test_case(total_mutant_index)
        return suspect

    # --------------------------------------------------------------- #

    def _save_actual_case_as_suspect(self, exc: exception.FuzzowskiError) -> Suspect:
        if self.save_crashes:
            suspect = Suspect(
                self._test_case_name(self._path, self.fuzz_node.mutant),
                self._path,
                self.nodes,
                self.total_mutant_index,
                self._receive_data_after_each_request,
                self._receive_data_after_fuzz,
                exc
            )

            if suspect not in self.suspects:
                self.suspects.append(suspect)
                self.export_file()

                # Increment number of crashes
                self.crashing_primitives[self.fuzz_node.mutant] = self.crashing_primitives.get(self.fuzz_node.mutant,
                                                                                               0) + 1
                self.crashing_primitives[self.fuzz_node] = self.crashing_primitives.get(self.fuzz_node, 0) + 1

                # Check if the element or the node reached the crashing threshold, and disable it
                if self.fuzz_node.mutant is not None and \
                        self.crashing_primitives[self.fuzz_node] >= self._crash_threshold_node:
                    self.fuzz_node.disabled = True
                    self._fuzz_data_logger.open_test_step(
                        "Crash threshold reached for this request, exhausting node {}.".format(self.fuzz_node.name))
                elif self.fuzz_node.mutant is not None and \
                        self.crashing_primitives[self.fuzz_node.mutant] >= self._crash_threshold_element:
                    if not isinstance(self.fuzz_node.mutant, primitives.Group) \
                            and not isinstance(self.fuzz_node.mutant, blocks.Repeat):
                        self._disable_current_element()
                        node_name = self._test_case_name(self._path, self.fuzz_node.mutant)
                        self._fuzz_data_logger.open_test_step(
                            "Crash threshold reached for this element, exhausting mutant {}.".format(node_name)
                        )
                return suspect

    # ================================================================#
    # CommandPrompt Overridden Functions and command handlers         #
    # ================================================================#

    def get_commands(self):
        commands = super().get_commands()
        commands.update({
            'print': {
                'desc': 'Print a test case by index',
                'exec': self._cmd_print_packets
            },
            'poc': {
                'desc': 'Print the python poc code of test case by index',
                'exec': self._cmd_print_poc
            },
            'fuzz': {
                'desc': 'Fuzz a test case by index',
                'exec': self._cmd_fuzz_single_case
            },
            'test': {
                'desc': 'Send the actual case without fuzzing',
                'exec': self._cmd_test_single_case
            },
            'goto': {
                'desc': 'Go to test case by index',
                'exec': self._cmd_go_to_test_case
            },
            'suspects': {
                'desc': 'print information about the tests suspected of crashing something',
                'exec': self._cmd_suspects
            },
            'suspects-del': {
                'desc': 'delete suspect',
                'exec': self._cmd_delsuspect
            },
            'crash': {
                'desc': 'print information about the crashes or add a new one. Saving the poc in the results folder',
                'exec': self._cmd_addcrash
            },
            'disable': {
                'desc': 'Disable the actual fuzzing element',
                'exec': self._cmd_disable_element
            },
            'disabled-elements': {
                'desc': 'List the disabled elements',
                'exec': self._cmd_list_disabled_elements
            },
            'enable': {
                'desc': 'Enable the disabled element passed as first argument',
                'exec': self._cmd_enable_element
            },
        })
        return commands

    # --------------------------------------------------------------- #

    def _cmd_print_packets(self, tokens):
        if len(tokens) > 0:
            mutant_index = int(tokens[0])
        else:
            mutant_index = self.total_mutant_index

        session_state = self._save_session_state()
        self._go_to_test_case(mutant_index)
        helpers.print_python(self._path, self.nodes)
        self._load_session_state(session_state)

    # --------------------------------------------------------------- #

    def _cmd_print_poc(self, tokens):
        if len(tokens) > 0:
            mutant_index = int(tokens[0])
        else:
            mutant_index = self.total_mutant_index
        session_state = self._save_session_state()
        self._go_to_test_case(mutant_index)
        helpers.print_poc(self.targets[0], self._path, self.nodes,
                          self._receive_data_after_each_request, self._receive_data_after_fuzz)

        self._load_session_state(session_state)

    # --------------------------------------------------------------- #

    def _cmd_fuzz_single_case(self, tokens):
        """
        Save actual state, fuzz single case (number) and restore state

        :param tokens: list of args, should have only an integer
        :return: None
        """
        self.save_crashes = False
        if len(tokens) > 0:
            indexrange = tokens[0].split('-')
            if len(indexrange) == 2:
                for mutant_index in range(int(indexrange[0]), int(indexrange[1])+1):
                    session_state = self._save_session_state()
                    self.fuzz_single_case(mutant_index)
                    self._load_session_state(session_state)
            elif len(indexrange) == 1:
                mutant_index = int(tokens[0])
                session_state = self._save_session_state()
                self.fuzz_single_case(mutant_index)
                self._load_session_state(session_state)
            else:
                print_formatted_text(HTML('<red>Wrong range format. Examples:\nfuzz 7\nfuzz100-120</red>'),
                                     style=self.get_style())
        else:
            mutant_index = self.total_mutant_index
            session_state = self._save_session_state()
            self.fuzz_single_case(mutant_index)
            self._load_session_state(session_state)
        self.save_crashes = True

    # --------------------------------------------------------------- #

    def _cmd_test_single_case(self, tokens):
        """
        Save actual state, fuzz single case (number) and restore state

        :param tokens: list of args, should have only an integer
        :return: None
        """
        self.is_paused = False
        try:
            self._test_normal_current_case(self._path)
            self._fuzz_data_logger.log_info("Test finished")
        except exception.FuzzowskiTargetConnectionFailedError:
            self._fuzz_data_logger.log_info("Target down")
        except Exception as e:
            self._fuzz_data_logger.log_info("Target down")
            self._fuzz_data_logger.log_info("Exception {}: {}".format(type(e).__name__, str(e)))
            raise
        self.is_paused = True

    # --------------------------------------------------------------- #

    def _cmd_skip_element(self, tokens):
        if self.fuzz_node.mutant is not None \
                and not isinstance(self.fuzz_node.mutant, primitives.Group) \
                and not isinstance(self.fuzz_node.mutant, blocks.Repeat):
            self.fuzz_node.reset()
            self.fuzz_node.mutant.reset()
            print(self.fuzz_node.mutant.name)

            print(self.fuzz_node.mutant.num_mutations())
            print(self.fuzz_node.mutant.mutant_index)
            skipped = self.fuzz_node.mutant.num_mutations() - self.fuzz_node.mutant.mutant_index
            test_case_name = self._test_case_name(self._path, self.fuzz_node.mutant)
            self._go_to_test_case(self.total_mutant_index + skipped + 1)
            print_formatted_text(HTML('Skipping <b>{}</b>. Exhausted <b>{}</b> test cases'
                                      .format(test_case_name, skipped)))

    # --------------------------------------------------------------- #

    def _cmd_disable_element(self, tokens):
        self._disable_current_element()

    def _disable_current_element(self):
        if self.fuzz_node.mutant is not None \
                and not isinstance(self.fuzz_node.mutant, primitives.Group) \
                and not isinstance(self.fuzz_node.mutant, blocks.Repeat):

            test_case_name = self._test_case_name(self._path, self.fuzz_node.mutant)
            element_path = '.'.join(test_case_name.split('.')[:-1])
            # print_formatted_text(HTML('Disabling element <b>{}</b>. '.format(element_path)))
            self._fuzz_data_logger.log_info(f'Disabling element {element_path}')
            self.fuzz_node.mutant.disabled = True
            if element_path not in self.disabled_elements:
                self.disabled_elements.append(element_path)

    def _disable_element_by_path(self, element_path):
        element = self._search_elem_by_path(element_path)
        element.disabled = True

    # --------------------------------------------------------------- #

    def _cmd_list_disabled_elements(self, tokens):
        for elem in self.disabled_elements:
            print(elem)

    def _cmd_enable_element(self, tokens):
        element_path = tokens[0]
        if element_path not in self.disabled_elements:
            print_formatted_text(HTML('<red>The path is not in the disabled elements list</red>'),
                                 style=self.get_style())
            return
        element = self._search_elem_by_path(element_path)
        element.disabled = False
        self.disabled_elements.remove(element_path)

    # --------------------------------------------------------------- #

    def _search_elem_by_path(self, element_path):
        request_name, element_name = element_path.split('.')
        request = self.find_node("name", request_name)
        return self._search_elem_by_name(request, element_name)

    def _search_elem_by_name(self, block, name):
        if block.name == name:
            return block

        if hasattr(block, 'stack'):
            for elem in block.stack:
                bl = self._search_elem_by_name(elem, name)
                if bl is not None:
                    return bl
        return None

    # --------------------------------------------------------------- #

    def _cmd_go_to_test_case(self, tokens):
        """
        Save actual state, fuzz single case (number) and restore state

        :param tokens: list of args, should have only an integer
        :return: None
        """
        mutant_index = int(tokens[0])
        # session_state = self._save_session_state()
        self._go_to_test_case(mutant_index)
        # self._load_session_state(session_state)

    # --------------------------------------------------------------- #

    def _cmd_suspects(self, tokens):
        if len(tokens) == 0:
            for crash in self.suspects:
                print_formatted_text(HTML('<redb>{}</redb>. {} [{}]'.format(crash.test_case, crash.test_case_name,
                                                                            crash.synopsis)),
                                     style=self.get_style())
        else:
            mutant_index = int(tokens[0])

    # --------------------------------------------------------------- #

    def _cmd_delsuspect(self, tokens):
        if len(tokens) == 0:
            print_formatted_text(HTML('<red>You need to select a suspect number to delete</red>'),
                                 style=self.get_style())
        else:
            mutant_index = int(tokens[0])
            try:
                suspect_to_delete = [suspect for suspect in self.suspects if suspect.test_case == mutant_index][0]
                self.suspects.remove(suspect_to_delete)
            except IndexError:
                print_formatted_text(HTML('<red>That suspect does not exist!</red>'),
                                     style=self.get_style())

    # --------------------------------------------------------------- #

    def _cmd_addcrash(self, tokens):

        if len(tokens) == 0:
            for crash in self.crashes:
                print_formatted_text(HTML('<redb>{}</redb>. {} [{}]'.format(crash.test_case, crash.test_case_name,
                                                                            crash.synopsis)),
                                     style=self.get_style())
        else:
            mutant_index = int(tokens[0])
            try:
                crash = [suspect for suspect in self.suspects if suspect.test_case == mutant_index][0]
                if crash not in self.crashes:
                    self.crashes.append(crash)
            except IndexError:
                # The crash is not a suspect, create a new one
                previous_index = self.total_mutant_index
                self._go_to_test_case(mutant_index)
                crash = Suspect(
                    self._test_case_name(self._path, self.fuzz_node.mutant),
                    self._path,
                    self.nodes,
                    self.total_mutant_index,
                    self._receive_data_after_each_request,
                    self._receive_data_after_fuzz,
                    None
                )
                if crash not in self.crashes:
                    self.crashes.append(crash)

                self._go_to_test_case(previous_index)


            previous_index = self.total_mutant_index
            self._go_to_test_case(mutant_index)

            poc_code = helpers.get_exploit_code(self.targets[0], self._path, self.nodes,
                                                self._receive_data_after_each_request, self._receive_data_after_fuzz)

            host = self.targets[0]._target_connection.host
            port = self.targets[0]._target_connection.port
            proto = self.targets[0]._target_connection.proto
            test_case_name = self._test_case_name(self._path, self.fuzz_node.mutant)

            poc_filename = os.path.join(constants.RESULTS_DIR,
                                        'poc_{}_{}_{}_{}.py'.format(host, port, proto, test_case_name))
            print_formatted_text(HTML('Writing PoC to file: <testn>{}</testn>'.format(poc_filename)),
                                 style=self.get_style())
            with open(poc_filename, 'w') as f:
                f.write(poc_code)
            self._go_to_test_case(previous_index)

    # --------------------------------------------------------------- #

    def _save_session_state(self) -> dict:
        state = {
            "index_start": self.total_mutant_index,
            "total_num_mutations": self.total_num_mutations,
            "total_mutant_index": self.total_mutant_index,

            "is_paused": self.is_paused,
            "session_filename": self.session_filename,
            "sleep_time": self.sleep_time,
            "restart_sleep_time": self.restart_sleep_time,
            "restart_interval": self.restart_interval,
            # "web_port": self.web_port,
            "crash_threshold": self._crash_threshold_node,

        }
        self._index_start = 0
        self._reset_fuzz_state()
        self.is_paused = False
        return state

    # --------------------------------------------------------------- #

    def _load_session_state(self, state: dict) -> None:
        self._reset_fuzz_state()
        self.is_paused = True

        # update the skip variable to pick up fuzzing from last test case.
        self._index_start = state["total_mutant_index"]
        self.session_filename = state["session_filename"]
        self.sleep_time = state["sleep_time"]
        self.restart_sleep_time = state["restart_sleep_time"]
        self.restart_interval = state["restart_interval"]
        # self.web_port = data["web_port"]
        self._crash_threshold_node = state["crash_threshold"]
        self.total_num_mutations = state["total_num_mutations"]
        self.total_mutant_index = state["total_mutant_index"]
        self.is_paused = state["is_paused"]

        self._go_to_test_case(self._index_start)

    def _go_to_test_case(self, test_case_index: int) -> None:
        self._index_start = test_case_index
        next(self._iterate_single_case_by_index(test_case_index))
        # self.fuzz_node.mutant._mutant_index = 0

    # --------------------------------------------------------------- #

    def handle_exit(self, tokens: list) -> None:
        if len(tokens) > 0:
            if tokens[0] in ('exit', 'quit', 'q'):
                self.export_file()
                sys.exit(0)

    # --------------------------------------------------------------- #

    def get_prompt(self):
        host = self.targets[0]._target_connection.host
        port = str(self.targets[0]._target_connection.port)

        return HTML('[<testn>{} of {}</testn>] '
                    '<b>➜</b> <host>{}</host>:<port>{}</port> $ '
                    .format(self.total_mutant_index, self.total_num_mutations, host, port))

    # --------------------------------------------------------------- #

    def get_style(self):
        return merge_styles([super().get_style(), Style.from_dict(constants.STYLE)])

    # --------------------------------------------------------------- #

    def intro_message(self):
        print_formatted_text(HTML('Fuzzing paused! Welcome to the <b>Fuzzowski Shell</b>'))

    # --------------------------------------------------------------- #

    def exit_message(self):
        print_formatted_text(HTML('<b>Exiting prompt...</b>'))

    # --------------------------------------------------------------- #

    def bottom_toolbar(self):
        if self._path is not None and self.fuzz_node is not None:
            test_case_name = self._test_case_name(self._path, self.fuzz_node.mutant)
            toolbar_message = HTML('Test Case [<bttestn>{}</bttestn>] of [<bttestn>{}</bttestn>]'
                                   ': Fuzzing <bttestn>{}</bttestn>'
                                   .format(self.total_mutant_index, self.total_num_mutations, test_case_name))
        else:
            toolbar_message = HTML('Test Case [<bttestn>{}</bttestn>] of [<bttestn>{}</bttestn>]'
                                   .format(self.total_mutant_index, self.total_num_mutations))

        return toolbar_message

    # --------------------------------------------------------------- #
