import attr


class FuzzowskiError(Exception):
    pass


class FuzzowskiRestartFailedError(FuzzowskiError):
    pass


class FuzzowskiConnectionError(FuzzowskiError):
    """ Parent class for connection errors"""
    pass


class FuzzowskiTargetConnectionFailedError(FuzzowskiConnectionError):
    pass


@attr.s
class FuzzowskiTargetConnectionAborted(FuzzowskiConnectionError):
    """
    Raised on `errno.ECONNABORTED`.
    """
    socket_errno = attr.ib()
    socket_errmsg = attr.ib()


class FuzzowskiTargetConnectionReset(FuzzowskiConnectionError):
    pass


class FuzzowskiTargetRecvTimeout(FuzzowskiConnectionError):
    pass

class FuzzowskiPaused(FuzzowskiError):
    pass


class FuzzowskiTestCaseAborted(FuzzowskiError):
    pass




class FuzzowskiRpcError(FuzzowskiError):
    pass


class FuzzowskiRuntimeError(Exception):
    pass


class SizerNotUtilizedError(Exception):
    pass


class MustImplementException(Exception):
    pass
