import os
import re
import sys
import time

from datetime import datetime
from subprocess import Popen, PIPE, call

from utils import get_module_name

from settings import SETTINGS

from logger import LOGINFO_IF_ENABLED
from logger import LOGERR_IF_ENABLED

SOURCE_MODULE = '[{0}] :: '.format(get_module_name(__file__))

p = call(["python", "./plugins/plg_cwe_updater.py"])

# Scheduler budet tut!!!

