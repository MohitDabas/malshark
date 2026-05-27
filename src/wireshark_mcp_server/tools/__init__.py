"""
Tool registration package.
Importing this package side-effects all @mcp.tool() decorators.
"""
from . import iocs          # noqa: F401
from . import credentials   # noqa: F401
from . import downloads     # noqa: F401
from . import beaconing     # noqa: F401
from . import summary       # noqa: F401
from . import capture       # noqa: F401
from . import http_sessions   # noqa: F401
from . import dns_tunneling   # noqa: F401
