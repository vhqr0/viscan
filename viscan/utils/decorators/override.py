def override(cls):
    def override(method):
        assert method.__name__ in dir(cls), \
            'override check failed'
        return method
    return override
