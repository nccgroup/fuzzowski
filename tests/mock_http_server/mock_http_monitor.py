from fuzzowski.monitors import IMonitor


class MockHTTPTestMonitor(IMonitor):
    @staticmethod
    def name() -> str:
        return "Mock_HTTP_Test_Monitor"

    @staticmethod
    def help():
        return ""

    def test(self) -> bool:
        conn = self.get_connection_copy()
        result = True
        return result