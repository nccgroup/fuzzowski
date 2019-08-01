from . import exception


class Suspect(object):

    def __init__(self, test_case_name: str, path: list, nodes:list, test_case: int,
                 receive_data_after_each_request: bool, receive_data_after_fuzz: bool,
                 exc: exception.FuzzowskiError):
        self.test_case_name = test_case_name
        # self.path = path
        # self.nodes = nodes
        self.test_case = test_case
        # self.receive_data_after_each_request = receive_data_after_each_request
        # self.receive_data_after_fuzz = receive_data_after_fuzz
        # self.exception = exc
        self.synopsis = exc.__class__.__name__

    # def get_packets(self):
    #     return printers.get_exploit_code(self.path, self.nodes, self.receive_data_after_each_request,
    #                                      self.receive_data_after_fuzz)

    def __repr__(self):
        return '{}. {} [{}]'.format(self.test_case, self.test_case_name, self.synopsis)

    def __eq__(self, other):
        return self.synopsis == other.synopsis and self.test_case == other.test_case
