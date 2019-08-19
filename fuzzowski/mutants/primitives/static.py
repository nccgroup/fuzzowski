from ..mutant import Mutant


class Static(Mutant):
    def __init__(self, value: bytes, name: str = None):
        """
        Primitive that contains static content.

        Args:
            value: The static value
            name:

        """

        # This is basically a non fuzzable mutant, nothing else to do here
        super().__init__(value, name, fuzzable=False)
