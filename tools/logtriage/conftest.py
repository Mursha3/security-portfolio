"""Pytest bootstrap.

This file exists so pytest puts the ``tools/logtriage`` directory on ``sys.path``
in every rootdir configuration, making ``import logtriage`` work without an
editable install.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
