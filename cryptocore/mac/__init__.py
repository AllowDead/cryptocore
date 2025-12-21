# cryptocore/mac/__init__.py
"""
MAC (Message Authentication Code) implementations.
Provides HMAC and optionally CMAC functionality.
"""

from cryptocore.mac.hmac import HMAC

__all__ = ['HMAC']