from typing import TypeVar, Any, Callable

T = TypeVar('T')


def override(cls: Any) -> Callable[[T], T]:

    def override(meth: T) -> T:
        assert getattr(meth, '__name__') in dir(cls), \
            'override check failed'
        return meth

    return override
