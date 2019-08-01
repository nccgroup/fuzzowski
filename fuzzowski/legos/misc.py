# Misc Types

from __future__ import absolute_import
from .. import blocks, primitives, exception


class DNSHostname(blocks.Block):
    def __init__(self, name, request, value, options=None):
        if not options:
            options = {}

        super(DNSHostname).__init__(name, request)

        self.value = value
        self.options = options

        if not self.value:
            raise exception.FuzzowskiRuntimeError("MISSING LEGO.tag DEFAULT VALUE")

        self.push(primitives.String(self.value))

    def render(self, replace_node=None, replace_value=None, original=False):
        """
        We overload and extend the render routine in order to properly insert substring lengths.
        """

        if replace_node is not None and replace_value is not None and replace_node == self.name:
            self._rendered = replace_value
            return self._rendered
        if original is True:
            return self.original_value

        # let the parent do the initial render.
        blocks.Block.render(self)

        new_str = ""

        # replace dots (.) with the substring length.
        for part in self._rendered.split("."):
            new_str += str(len(part)) + part

        # be sure to null terminate too.
        self._rendered = new_str + "\x00"

        return self._rendered


class Tag(blocks.Block):
    def __init__(self, name, request, value, options=None):
        if not options:
            options = {}

        super(Tag, self).__init__(name, request)

        self.value = value
        self.options = options

        if not self.value:
            raise exception.FuzzowskiRuntimeError("MISSING LEGO.tag DEFAULT VALUE")

        # <example>
        # [delim][string][delim]

        self.push(primitives.Delim("<"))
        self.push(primitives.String(self.value))
        self.push(primitives.Delim(">"))
