from ..exception import FuzzowskiRuntimeError
from typing import Dict, List, Any, Generator
from .edge import Edge

class Graph(object):
    def __init__(self):
        self.graph_dict: Dict[Any, List] = dict()
        self.root = '_root_'
        self.graph_dict[self.root] = []

    def connect(self, src: object, dst=None, callback=None):

        if dst is None:  # Node connected to root
            edge = Edge(self.root, src, callback)
        else:
            edge = Edge(src, dst, callback)

        if self.contains(edge.src, edge.dst):
            raise FuzzowskiRuntimeError(f'{edge} was already in the graph')
        if self.path_exists(edge.dst, edge.src):
            raise FuzzowskiRuntimeError(f'{edge} would create a bucle')

        if edge.src not in self.graph_dict:
            # Connect to root and also add the connection
            self.graph_dict[edge.src] = [edge]
            root_edge = Edge(self.root, src, callback)
            self.graph_dict[root_edge.src].append(root_edge)

        else:
            self.graph_dict[edge.src].append(edge)

        if edge.dst not in self.graph_dict:
            self.graph_dict[edge.dst] = []

    def contains(self, src: object, dst: object) -> bool:
        """
        Args:
            src: src object
            dst: dst object

        Returns: True if an Edge(src, dst) exists in the graph
        """
        if src not in self.graph_dict:
            return False
        else:
            edges = self.graph_dict[src]
            for edge in edges:
                if edge.src == src and edge.dst == dst:
                    return True
            return False

    def edges_from(self, src: object) -> List[Edge]:
        """
        Args:
            src: object to get the edges from

        Returns:
            A List of Edges with the specified source
        """
        try:
            return self.graph_dict[src]
        except KeyError:
            return []

    def path_iterator(self) -> Generator[List[Edge], None, None]:
        """
        This iterator iterate through all the possible paths in the graph

        Returns: a generator that yields full paths of edges
        """
        src = self.root
        yield from self._path_iterator_recursive(src, [])

    def _path_iterator_recursive(self, src: object, path: list) -> Generator[List[Edge], None, None]:
        edges = self.edges_from(src)
        if len(edges) > 0:
            for edge in edges:
                new_path = path.copy()
                new_path.append(edge)
                yield from self._path_iterator_recursive(edge.dst, new_path)
        else:  # leaf
            yield path

    def path_exists(self, src: object, dst: object):
        found = False
        for edge in self.edges_from(src):
            found = edge.dst == dst or self.path_exists(edge.dst, dst)
            if found:
                return True
        return found
