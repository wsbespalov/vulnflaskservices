import os
import re
import sys
import zlib
import time
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from datetime import datetime
from subprocess import Popen, PIPE

from diskcache import Deque

from flask import Flask

baseDir = os.path.dirname(os.path.abspath(os.path.dirname(__file__)))
sys.path.append(baseDir)

from utils import get_module_name

from settings import SETTINGS

from logger import LOGINFO_IF_ENABLED
from logger import LOGERR_IF_ENABLED

MODULE_NAME = get_module_name(__file__)
SOURCE_MODULE = '[{0}] :: '.format(MODULE_NAME)
CWE_HOST = 'localhost'
CWE_PORT = 3000

from state import State
from state import decode as decode_state

from plugins.updater import Updater
from plugins.observer import LogObserver
from plugins.observer import RedisObserver
from plugins.observer import RedisHistoryObserver


log_observer = LogObserver(MODULE_NAME)
redis_observer = RedisObserver(MODULE_NAME)
redis_history_observer = RedisHistoryObserver(MODULE_NAME)


class CWEHandler(ContentHandler):
    def __init__(self):
        self.cwe = []
        self.description_summary_tag = False
        self.weakness_tag = False

    def startElement(self, name, attrs):
        if name == 'Weakness':
            self.weakness_tag = True
            self.statement = ""
            self.weaknesses = attrs.get('Weakness_Abstraction')
            self.name = attrs.get('Name')
            self.idname = attrs.get('ID')
            self.status = attrs.get('Status')
            self.cwe.append({
                'name': self.name,
                'id': self.idname,
                'status': self.status,
                'weaknesses': self.weaknesses})
        elif name == 'Description_Summary' and self.weakness_tag:
            self.description_summary_tag = True
            self.description_summary = ""

    def characters(self, ch):
        if self.description_summary_tag:
            self.description_summary += ch.replace("       ", "")

    def endElement(self, name):
        if name == 'Description_Summary' and self.weakness_tag:
            self.description_summary_tag = False
            self.description_summary = self.description_summary + self.description_summary
            self.cwe[-1]['description_summary'] = self.description_summary.replace("\n", "")
        elif name == 'Weakness':
            self.weakness_tag = False


class CWEUpdater(Updater):

    def __init__(self):
        super(CWEUpdater, self).__init__()


cwe_updater_machine = CWEUpdater()
cwe_updater_machine.attach(log_observer)


app = Flask(MODULE_NAME)


@app.route('/')
def index():
    return 'Service: [{}], State: [{}]'.format(MODULE_NAME, decode_state(cwe_updater_machine.subject_state))


@app.route('/state')
def state():
    return str(cwe_updater_machine.subject_state)


@app.route('/next')
def next():
    cwe_updater_machine.step()
    return 'set the next state: {}'.format(cwe_updater_machine.subject_state)


def main():
    cwe_updater_machine.subject_state = State.idle.value
    app.run(host=CWE_HOST, port=CWE_PORT, debug=True)


if __name__ == '__main__':
    main()
