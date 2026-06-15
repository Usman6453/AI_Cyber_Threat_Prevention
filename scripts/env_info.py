import sys, platform
from pathlib import Path
print('python_executable=', sys.executable)
print('python_version=', sys.version)
print('platform_machine=', platform.machine())
print('platform_architecture=', platform.architecture())
try:
    import PyQt6
    from PyQt6.QtCore import QT_VERSION_STR
    from PyQt6 import QtCore
    print('PyQt6 import ok')
    try:
        print('QT_VERSION_STR=', QT_VERSION_STR)
    except Exception:
        pass
    try:
        print('QtCore.PYQT_VERSION_STR=', QtCore.PYQT_VERSION_STR)
    except Exception:
        pass
except Exception as e:
    print('PyQt6 import failed:', e)
