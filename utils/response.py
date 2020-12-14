#coding=utf-8
class ReturnCode:
    def __init__(self):
        pass
    SUCCESS = 0
    FAILED = 100
    RESOURCE_NOT_EXISTS = 404
    UNAUTHORIZED = 403
    INTERVAL_SERVER_ERROR = 500
    BROKEN_AUTHORIZED_DATA = 501
    WRONG_PARAMS = 101

    @classmethod
    def errmsg(cls, code):
        if code == cls.SUCCESS:
            return ''
        elif code == cls.FAILED:
            return 'failed'
        elif code == cls.UNAUTHORIZED:
            return 'unauthorized'
        elif code == cls.WRONG_PARAMS:
            return 'wrong params'
        elif code == cls.RESOURCE_NOT_EXISTS:
            return 'resource_not_exists'
        elif code == cls.INTERVAL_SERVER_ERROR:
            return 'interval server error'
        elif code == cls.BROKEN_AUTHORIZED_DATA:
            return 'broken_authorized_data'
        else:
            return 'unknow error'


# 被Mixin取代前
def wrap_json_response(data=None, code=None, message=None):
    response = {}
    if not code:
        code = ReturnCode.SUCCESS
    if not message:
        message = ReturnCode.errmsg(code)
    if data:
        response['data'] = data
    else:
        response['data'] = ''
    response['errno'] = code
    response['errmsg'] = message
    return response


# 被Mixin取代后
class CommonResponseMixin(object):
    @classmethod
    def wrap_json_response(cls, data=None, code=None, errmsg=None):
        response = {}
        if not code:
            code = ReturnCode.SUCCESS
        if not errmsg:
            errmsg = ReturnCode.errmsg(code)
        if data:
            response['data'] = data
        else:
            response['data'] = ''
        response['errno'] = code
        response['errmsg'] = errmsg
        return response
