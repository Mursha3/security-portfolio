"""Pytest bootstrap.

This file exists so pytest puts the ``tools/webaudit`` directory on ``sys.path``
in every rootdir configuration, making ``import webaudit`` work without an
editable install.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
