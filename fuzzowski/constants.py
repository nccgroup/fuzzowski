BIG_ENDIAN = ">"
LITTLE_ENDIAN = "<"

RESULTS_DIR = 'fuzzowski-results'

ERR_CONN_FAILED_TERMINAL = "Cannot connect to target; target presumed down. Stopping test run. Note: This likely " \
                           "indicates a failure caused by the previous test case. "

# ERR_CONN_FAILED = "Cannot connect to target; target presumed down. Note: This likely " \
#                   "indicates a failure caused by the previous test case. "

# ERR_CONN_FAILED_RETRY = "Cannot connect to target; Retrying... "

# ERR_CONN_ABORTED = "Target connection lost (socket error: {socket_errno} {socket_errmsg}): You may have a " \
#                    "network issue, or an issue with firewalls or anti-virus. Try " \
#                    "disabling your firewall."

# ERR_CONN_RESET = "Target connection reset."

ERR_CONN_RESET_FAIL = "Target connection reset -- considered a failure case when triggered from post_send"

ERR_CONN_TIMEOUT = 'Timeout'

# Styles for other
STYLE = {
    'host': 'DeepSkyBlue bold',
    'port': 'DeepSkyBlue bold',
    'testn': 'gold bold',
    'bttestn': 'bg:gold bold',
    'red': 'red',
    'redb': 'red bold',
    'bottom-toolbar': 'darkslategray bg:white',
    'w': 'bg:white nobold',

    # Message types
    'error': 'bold bg:red fg:white',
    'fail': 'bold red',
    'test_case': 'bold gold',
    'step': 'bold violet',
    'send': 'cyan',
    'receive': 'cyan',
    'pass': 'bold green',
    'warning': 'bold orange',

    }
