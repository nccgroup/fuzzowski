import collections

from prompt_toolkit.completion import Completer, Completion, CompleteEvent
from prompt_toolkit.document import Document

from ..helpers import get_tokens

class CommandCompleter(Completer):
    def __init__(self, commands) -> None:
        super().__init__()
        self.commands = commands

    def find_completions(self, document: Document) -> dict:
        tokens = get_tokens(document.text)
        suggestions = {}
        current = self.commands
        for token in tokens:
            candidate = token.lower()
            if candidate in list(current.keys()):
                # if there are sub commands, grab them
                if 'cmds' in current[candidate]:
                    current = current[candidate]['cmds']
                else:
                    return {}

        if current and len(current) > 0:
            for k, _ in current.items():
                # fuzzy-ish matching when part of a word is in a suggestion
                if document.get_word_before_cursor().lower() in k.lower():
                    suggestions[k] = current[k]
        return suggestions

    def get_completions(self, document: Document, complete_event: CompleteEvent) -> Completion:
        commands = {}
        # get the stuff we have typed so far
        before_cursor = document.get_word_before_cursor()
        commands.update(self.find_completions(document))

        # if there are commands, show them
        if len(commands) > 0:
            commands = collections.OrderedDict(sorted(list(commands.items()), key=lambda t: t[0]))
            for cmd, extra in commands.items():
                desc = extra['desc'] if type(extra) is dict and 'desc' in extra else None
                # finally, yield the generator for completions
                yield Completion(cmd, -(len(before_cursor)), display_meta=desc)

