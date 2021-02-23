from fuzzowski.exception import FuzzowskiRuntimeError
from ..mutant import Mutant
from typing import List, Generator


class Block(Mutant):
    def __init__(self, name: str, request: 'Request', group: str = None, encoder: callable = None,
                 dep: str = None, dep_value: object = None, dep_values: List = None, dep_compare: str = "=="):
        """
        The basic building block. Can contain primitives, sizers, checksums or other blocks (any Mutant).

        Args:
            name:           Name of the new block
            request:        Request this block belongs to
            group:          Name of group to associate this block with
            encoder:        (Optional, def=None) Optional pointer to a function to pass rendered data to prior to return
            dep:            (Optional, def=None) Optional primitive whose specific value this block is dependant on
            dep_value:      (Optional, def=None) Value that field "dep" must contain for block to be rendered
            dep_values:     (Optional, def=[]) Values that field "dep" may contain for block to be rendered
            dep_compare:    (Optional, def="==") Comparison method to apply to dependency (==, !=, >, >=, <, <=)
        """

        self._name = name
        self.request = request
        self.group = group
        self.encoder = encoder
        self.dep = dep
        self.dep_value = dep_value
        self.dep_values = dep_values
        self.dep_compare = dep_compare

        self.stack: List[Mutant] = []  # block item stack.
        self._rendered = ""  # rendered block contents.
        self._fuzzable = True  # blocks are always fuzzable because they may contain fuzzable items.
        self.group_idx = 0  # if this block is tied to a group, the index within that group.
        self._fuzz_complete = False  # whether or not we are done fuzzing this block.
        self._mutant_index = 0  # current mutation index.
        self._disabled = False  # Blocks cannot be disabled

        self._mutation_gen = self._mutation_generator()

    @property
    def original_value(self):
        original_value = b""

        for item in self.stack:
            original_value += item.original_value

        if self.encoder:
            original_value = self.encoder(original_value)

        return original_value

    def mutation_generator(self, mutant_index=0) -> Generator[bytes, None, None]:
        # self.reset()
        self.goto(mutant_index)
        return self._mutation_gen

    def _mutation_generator(self):
        # if self.mutant_index != 0:
        #     yield self.render()  # We want to render the first value of the generator when we go with goto

        # Iterate over all fuzzable mutants, choosing one to be the actual mutant each time
        for item in self.stack:  # First pass - Take any mutable item
            if item.fuzzable and item.num_mutations > 0:
                # Update request with actual mutant
                if not isinstance(item, Block) and self.request is not None:
                    self.request.mutant = item
                self.actual_mutant = item
                self.mutant_generator = item.mutation_generator()

                # For each mutation, render everything and yield it
                for mutation in self.mutant_generator:
                    self._mutant_index += 1
                    yield self.render()

        # TODO: If a group is attached, repeat the process above for each mutation of the group

        # After finishing, update Request removing the mutant
        self.request.mutant = None
        self.reset()

    def render(self, replace_node: str = None, replace_value: bytes = None, original: bool = False) -> bytes:
        """
        Step through every item on this blocks stack and render it. Subsequent blocks recursively render their stacks.
        """
        self._rendered = b""

        if replace_node is not None and replace_value is not None and replace_node == self.name:
            self._rendered = replace_value
            return self._rendered

        #
        # if this block is dependant on another field and the value is not met, render nothing.
        # TODO: dep related code left for compatibility, not totally sure when to use this
        if self.dep:
            return self._render_dep()

        # Otherwise, render and encode as usual.
        for item in self.stack:
            self._rendered += item.render(replace_node=replace_node, replace_value=replace_value, original=original)

        # add the completed block to the request dictionary.
        # TODO: Is this necessary?
        # self.request.closed_blocks[self.name] = self

        # if an encoder was attached to this block, call it.
        if self.encoder:
            self._rendered = self.encoder(self._rendered)

        return self._rendered

    def _render_dep(self):
        if self.dep_compare == "==":
            if self.dep_values and self.request.names[self.dep]._value not in self.dep_values:
                self._rendered = b""
                return self._rendered

            elif not self.dep_values and self.request.names[self.dep]._value != self.dep_value:
                self._rendered = b""
                return self._rendered

        if self.dep_compare == "!=":
            if self.dep_values and self.request.names[self.dep]._value in self.dep_values:
                self._rendered = b""
                return self._rendered

            elif self.request.names[self.dep]._value == self.dep_value:
                self._rendered = b""
                return self._rendered

        if self.dep_compare == ">" and self.dep_value <= self.request.names[self.dep]._value:
            self._rendered = b""
            return self._rendered

        if self.dep_compare == ">=" and self.dep_value < self.request.names[self.dep]._value:
            self._rendered = b""
            return self._rendered

        if self.dep_compare == "<" and self.dep_value >= self.request.names[self.dep]._value:
            self._rendered = b""
            return self._rendered

        if self.dep_compare == "<=" and self.dep_value > self.request.names[self.dep]._value:
            self._rendered = b""
            return self._rendered

    @property
    def num_mutations(self):
        """
        Determine the number of repetitions we will be making.

        @rtype:  int
        @return: Number of mutated forms this primitive can take.
        """

        num_mutations = 0

        for item in self.stack:
            if item.fuzzable:
                num_mutations += item.num_mutations

        # if this block is associated with a group, then multiply out the number of possible mutations.
        # TODO: Multiply when adding groups
        # if self.group:
        #    num_mutations *= len(self.request.names[self.group].values)

        return num_mutations

    def push(self, item: Mutant):
        """
        Push an arbitrary item onto this blocks stack.
        """
        self.stack.append(item)

    def reset(self):
        """
        Reset the primitives on this blocks stack to the starting mutation state.
        """
        self.goto(0)

    def _reset(self):
        self._fuzz_complete = False
        self.group_idx = 0
        # Update Request removing the mutant
        self.request.mutant = None
        self._mutant_index = 0

        for item in self.stack:
            if item.fuzzable:
                item.reset()

    def goto(self, mutant_index: int):
        if mutant_index > self.num_mutations:
            raise FuzzowskiRuntimeError(f"Mutant tried to get mutation "
                                        f"{mutant_index} > num_mutations ({self.num_mutations})")
        elif mutant_index == 0:
            self._reset()
            self._mutation_gen = self._mutation_generator()
        else:
            # Iterate through mutations until reaching the desired mutant_index
            self.reset()
            i = 0
            self._mutation_gen = self._mutation_generator()
            while i < mutant_index:
                next(self._mutation_gen)  # The mutation_generator will change everything
                i += 1

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, self.name)

    def __len__(self):
        if self.encoder is not None:
            return len(self.render())
        else:
            return sum(len(item.render()) for item in self.stack)

    def list_fuzzable_mutants(self):
        fuzzable_items = []
        for item in self.stack:
            if isinstance(item, Block):
                fuzzable_items.extend(item.list_fuzzable_mutants())
            else:
                if item.fuzzable:
                    fuzzable_items.append(item)
        return fuzzable_items

    """
    def _mutate(self):
        mutated = False

        # are we done with this block?
        if self._fuzz_complete:
            return False

        #
        # mutate every item on the stack for every possible group value.
        #
        if self.group:
            group_count = self.request.names[self.group].num_mutations()

            # update the group value to that at the current index.
            self.request.names[self.group]._value = self.request.names[self.group].values[self.group_idx]

            # mutate every item on the stack at the current group value.
            for item in self.stack:
                if item.fuzzable and item.mutate():
                    mutated = True

                    if not isinstance(item, Block):
                        self.request.mutant = item
                    break

            # if the possible mutations for the stack are exhausted.
            if not mutated:
                # increment the group value index.
                self.group_idx += 1

                # if the group values are exhausted, we are done with this block.
                if self.group_idx == group_count:
                    # restore the original group value.
                    self.request.names[self.group].reset()

                # otherwise continue mutating this group/block.
                else:
                    # update the group value to that at the current index.
                    self.request.names[self.group]._value = self.request.names[self.group].values[self.group_idx]

                    # this the mutate state for every item in this blocks stack.
                    # NOT THE BLOCK ITSELF THOUGH! (hence why we didn't call self.reset())
                    for item in self.stack:
                        if item.fuzzable:
                            item.reset()

                    # now mutate the first field in this block before continuing.
                    # (we repeat a test case if we don't mutate something)
                    for item in self.stack:
                        if item.fuzzable and item.mutate():
                            mutated = True

                            if not isinstance(item, Block):
                                self.request.mutant = item

                            break
        #
        # no grouping, mutate every item on the stack once.
        #
        else:
            for item in self.stack:
                if item.fuzzable and item.mutate():
                    mutated = True

                    if not isinstance(item, Block):
                        self.request.mutant = item

                    break

        # if this block is dependant on another field, then manually update that fields value appropriately while we
        # mutate this block. we'll restore the original value of the field prior to continuing.
        if mutated and self.dep:
            # if a list of values was specified, use the first item in the list.
            if self.dep_values:
                self.request.names[self.dep]._value = self.dep_values[0]

            # if a list of values was not specified, assume a single value is present.
            else:
                self.request.names[self.dep]._value = self.dep_value

        # we are done mutating this block.
        if not mutated:
            self._fuzz_complete = True

            # if we had a dependency, make sure we restore the original value.
            if self.dep:
                self.request.names[self.dep].reset()

        return mutated
    """
