class PassiveScanner:
    """Temporary scanner entry point.

    For now it only receives traffic records. Add vulnerability checks here later.
    """

    def check(self, record):
        request = record["request"]
        response = record["response"]

        # This is only a first-step demo rule, used to prove traffic is flowing.
        if response["status_code"] >= 500:
            print(f'[possible issue] Server error: {request["method"]} {request["url"]}')
