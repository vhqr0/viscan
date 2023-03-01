from typing import TypeVar, Any
from collections.abc import Callable

Meth = TypeVar('Meth')


# Links:
#   https://stackoverflow.com/questions/1167617/in-python-how-do-i-indicate-im-overriding-a-method
#   https://github.com/mkorpela/overrides
def override(cls: Any) -> Callable[[Meth], Meth]:
    """Check for overrides without losing type hints."""

    def override(meth: Meth) -> Meth:
        assert getattr(meth, '__name__') in dir(cls), \
            'override check failed'
        return meth

    return override
