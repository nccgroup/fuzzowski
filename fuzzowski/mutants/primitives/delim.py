from fuzzowski.mutants.mutant import Mutant


class Delim(Mutant):
    def __init__(self, value, fuzzable: bool = True, name: str = None):
        """
        Represent a delimiter such as :,\r,\n, ,=,>,< etc... Mutations include repetition, substitution and exclusion.
        
        Args:
            value:      Original value
            fuzzable:   (Optional, def=True) Enable/disable fuzzing of this primitive
            name:       (Optional, def=None) Specifying a name gives you direct access to a primitive
        """

        mutations = [value * 2,
                     value * 5,
                     value * 10,
                     value * 25,
                     value * 100,
                     value * 500,
                     value * 1000,
                     "",
                     " ",
                     "\t",
                     "\t" * 2,
                     "\t" * 100,
                     "\t " * 100,
                     "\t\r\n" * 100,
                     "!",
                     "@",
                     "#",
                     "$",
                     "%",
                     "^",
                     "&",
                     "*",
                     "(",
                     ")",
                     "-",
                     "_",
                     "+",
                     "=",
                     ":",
                     ": " * 100,
                     ":7" * 100,
                     ";",
                     "'",
                     "\"",
                     "/",
                     "\\",
                     "?",
                     "<",
                     ">",
                     ".",
                     ",",
                     "\r",
                     "\n",
                     "\r\n" * 64,
                     "\r\n" * 128,
                     "\r\n" * 512]

        # The Mutant behaviour is perfect for this one :)
        super().__init__(value, name=name, fuzzable=fuzzable, mutations=mutations)
