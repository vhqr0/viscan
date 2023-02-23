from typing import TypeVar, Any, Callable

T = TypeVar('T')


# Links:
#   https://stackoverflow.com/questions/1167617/in-python-how-do-i-indicate-im-overriding-a-method
#   https://github.com/mkorpela/overrides
def override(cls: Any) -> Callable[[T], T]:
    """Check for overrides without losing type hints."""

    def override(meth: T) -> T:
        assert getattr(meth, '__name__') in dir(cls), \
            'override check failed'
        return meth

    return override
