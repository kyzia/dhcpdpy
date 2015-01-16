# -*- coding: utf-8 -*-

class LUIAPIError(Exception):
    pass

class LUIAPIResultError(Exception):
    def __init__(self, code, message, *args):
        super(LUIAPIResultError, self).__init__(message.format(*args) if args else message)
        self.code = code

class LUIAPIClientError(LUIAPIError):
    pass

class LUIAPIServerError(LUIAPIError):
    pass

class LUIAPIServerSoftError(LUIAPIServerError):
    pass

class LUIAPIServerHardError(LUIAPIServerError):
    pass

class LUIAPIWireError(LUIAPIClientError):
    pass

class LUIAPIConnectError(LUIAPIWireError):
    pass

class LUIAPIEncodeError(LUIAPIClientError):
    pass

class LUIAPIDecodeError(LUIAPIClientError):
    pass
