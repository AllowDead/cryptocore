from cryptocore.modes.ecb import ECBMode
from cryptocore.modes.cbc import CBCMode
from cryptocore.modes.cfb import CFBMode
from cryptocore.modes.ofb import OFBMode
from cryptocore.modes.ctr import CTRMode

# GCM импортируем только если нужен, чтобы избежать циклических импортов
__all__ = ['ECBMode', 'CBCMode', 'CFBMode', 'OFBMode', 'CTRMode']

# Функция для ленивой загрузки GCM
def get_gcm_class():
    from .gcm import GCM, AuthenticationError
    return GCM, AuthenticationError