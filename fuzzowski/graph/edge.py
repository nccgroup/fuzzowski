class Edge(object):

    def __init__(self, src: object, dst: object, callback: callable = None):
        """
        Extends pgraph.edge with a callback option. This allows us to register a function to call between node
        transmissions to implement functionality such as challenge response systems. The callback method must follow
        this prototype::

            def callback(target, logger, session, node, edge, original=False, *args, **kwargs)

        Where node is the node about to be sent, edge is the last edge along the current fuzz path to "node", session
        is a pointer to the session instance which is useful for snagging data such as session.last_recv which contains
        the data returned from the last socket transmission and sock is the live socket. A callback is also useful in
        situations where, for example, the size of the next packet is specified in the first packet.

        Args:
            src (int): Edge source ID
            dst (int): Edge destination ID
            callback (function): Optional. Callback function to pass received data to between node xmits
        """

        self.src = src
        self.dst = dst
        self.callback = callback

    def __repr__(self):
        if self.callback is not None:
            return f'<Edge ({self.src} -> {self.dst}), [{self.callback.__name__}]>'
        else:
            return f'<Edge ({self.src} -> {self.dst})>'
