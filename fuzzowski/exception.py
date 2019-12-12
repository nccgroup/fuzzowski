import attr


class FuzzowskiError(Exception):
    pass


class FuzzowskiRestartFailedError(FuzzowskiError):
    pass


class FuzzowskiTargetConnectionFailedError(FuzzowskiError):
    pass


class FuzzowskiPaused(FuzzowskiError):
    pass


class FuzzowskiTestCaseAborted(FuzzowskiError):
    pass


class FuzzowskiTargetConnectionReset(FuzzowskiError):
    pass


class FuzzowskiTargetRecvTimeout(FuzzowskiError):
    pass


@attr.s
class FuzzowskiTargetConnectionAborted(FuzzowskiError):
    """
    Raised on `errno.ECONNABORTED`.
    """
    socket_errno = attr.ib()
    socket_errmsg = attr.ib()


class FuzzowskiRpcError(FuzzowskiError):
    pass


class FuzzowskiRuntimeError(Exception):
    pass


class SizerNotUtilizedError(Exception):
    pass


class MustImplementException(Exception):
    pass
