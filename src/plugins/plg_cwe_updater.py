#!/usr/bin/env python
import os
import sys
import json
from xml.sax import make_parser
from xml.sax.handler import ContentHandler

from flask import Flask

baseDir = os.path.dirname(os.path.abspath(os.path.dirname(__file__)))
sys.path.append(baseDir)

from utils import get_file
from utils import get_module_name
from utils import check_internet_connection

from settings import SETTINGS

from logger import LOGINFO_IF_ENABLED
from logger import LOGERR_IF_ENABLED

from state import State
from state import decode as decode_state

from plugins.subject import Subject
from plugins.updater import Updater
from plugins.observer import LogObserver
from plugins.observer import RedisObserver
from plugins.observer import RedisHistoryObserver

from diskcache import Deque
disk_cache_file = './diskcache/cwe/'

from caches import store

MODULE_NAME = get_module_name(__file__)
SOURCE_MODULE = '[{0}] :: '.format(MODULE_NAME)
CWE_HOST = 'localhost'
CWE_PORT = 3000

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


class CWEUpdater(Subject, Updater):
    data_from_source = []
    parsed_items = []
    response_from_source = None
    disk_cache = None

    def __init__(self):
        self.disk_cache = Deque(directory=disk_cache_file)
        super(CWEUpdater, self).__init__()

    def start(self):
        LOGINFO_IF_ENABLED(SOURCE_MODULE, '[s] Step: start')
        pass

    def pending(self):
        LOGINFO_IF_ENABLED(SOURCE_MODULE, '[s] Step: pending')
        if check_internet_connection():
            LOGINFO_IF_ENABLED(SOURCE_MODULE, '[+] Internet connection is stable')
            return True
        LOGINFO_IF_ENABLED(SOURCE_MODULE, '[-] Internet connection is not stable')
        return False

    def downloading(self):
        source = SETTINGS.get("cwe", {}).get("source", "http://cwe.mitre.org/data/xml/cwec_v2.8.xml.zip")
        LOGINFO_IF_ENABLED(SOURCE_MODULE, '[s] Step: downloading')
        try:
            LOGINFO_IF_ENABLED(SOURCE_MODULE, '[+] Download source file')
            self.data_from_source, self.response_from_source = get_file(getfile=source)
            LOGINFO_IF_ENABLED(SOURCE_MODULE, '[+] Downloading complete')
            return True
        except Exception as ex:
            LOGERR_IF_ENABLED(SOURCE_MODULE, "[-] Got exception during downloading CWE source: {0}".format(ex))
            return False

    def parsing(self):
        LOGINFO_IF_ENABLED(SOURCE_MODULE, '[s] Step: parsing')
        if 'error' not in self.response_from_source:
            self.parsed_items = []
            parser = make_parser()
            cwe_handler = CWEHandler()
            parser.setContentHandler(cwe_handler)
            LOGINFO_IF_ENABLED(SOURCE_MODULE, '[+] Start parsing CWE data')
            parser.parse(self.data_from_source)
            LOGINFO_IF_ENABLED(SOURCE_MODULE, '[+] Complete parsing CWE data')
            for cwe in cwe_handler.cwe:
                cwe['description_summary'] = cwe['description_summary'].replace("\t\t\t\t\t", " ")
                self.parsed_items.append(cwe)
            self.data_from_source = []
            LOGINFO_IF_ENABLED(SOURCE_MODULE, '[+] Parsing complete')
            return True
        else:
            LOGERR_IF_ENABLED(SOURCE_MODULE, '[-] Got "error" in response')
            return False

    def caching_local(self):
        LOGINFO_IF_ENABLED(SOURCE_MODULE, '[s] Step: caching_local')
        try:

            self.disk_cache.clear()

            for data in self.parsed_items:
                self.disk_cache.append(data)

            if len(self.disk_cache) == len(self.parsed_items):
                self.parsed_items = []
                LOGINFO_IF_ENABLED(SOURCE_MODULE, '[+] Caching local complete')
                return True
            else:
                LOGERR_IF_ENABLED(SOURCE_MODULE, '[-] Got error (length not equals) with write DiskCache collection')
                return False
        except Exception as ex:
            LOGERR_IF_ENABLED(SOURCE_MODULE, '[-] Got exception with caching local: {}'.format(ex))
            return False

    def caching_global(self):
        LOGINFO_IF_ENABLED(SOURCE_MODULE, '[s] Step: caching_global')
        try:
            collection = MODULE_NAME + '::cache'

            try:
                store.delete(collection)
            except Exception as ex:
                LOGERR_IF_ENABLED(SOURCE_MODULE, '[-] Got exception with delete Redis collection: {}'.format(ex))
                return False

            for i in range(len(self.disk_cache)):
                try:
                    data = self.disk_cache.pop()
                except Exception as ex:
                    LOGERR_IF_ENABLED(SOURCE_MODULE, '[-] Got exception with delete Redis collection: {}'.format(ex))
                    return False

                try:
                    store.rpush(collection, json.dumps(data))
                except Exception as ex:
                    LOGERR_IF_ENABLED(SOURCE_MODULE, '[-] Got exception with write Redis: {}'.format(ex))
                    return False
            if store.llen(collection) == len(self.parsed_items):
                LOGINFO_IF_ENABLED(SOURCE_MODULE, '[+] Caching global complete')
                return True
            else:
                LOGERR_IF_ENABLED(SOURCE_MODULE, '[-] Got error (length not equals) with write Redis collection')
                return False
        except Exception as ex:
            LOGERR_IF_ENABLED(SOURCE_MODULE, '[-] Got exception with caching global: {}'.format(ex))
            return False

    def write_database(self):
        LOGINFO_IF_ENABLED(SOURCE_MODULE, '[s] Step: write_database')
        return True
        # LOGINFO_IF_ENABLED(SOURCE_MODULE, '[s] Step: write_database')
        # try:
        #     LOGINFO_IF_ENABLED(SOURCE_MODULE, '[+] Write database complete')
        #     return True
        # except Exception as ex:
        #     LOGERR_IF_ENABLED(SOURCE_MODULE, '[-] Got exception with caching global: {}'.format(ex))
        #     return False

    def idle(self):
        LOGINFO_IF_ENABLED(SOURCE_MODULE, '[s] Step: idle')
        return True

    def finish(self):
        LOGINFO_IF_ENABLED(SOURCE_MODULE, '[s] Step: finish')
        return True

    def undefined(self):
        LOGINFO_IF_ENABLED(SOURCE_MODULE, '[s] Step: undefined')
        return True


cwe_updater_machine = CWEUpdater()
cwe_updater_machine.attach(log_observer)
cwe_updater_machine.attach(redis_observer)
cwe_updater_machine.attach(redis_history_observer)


app = Flask(MODULE_NAME)


@app.route('/')
def index():
    return 'Service: [{}], State: [{}]'.format(MODULE_NAME, decode_state(cwe_updater_machine.subject_state))


@app.route('/state')
def state():
    return str(cwe_updater_machine.subject_state)


@app.route('/start')
def start():
    current_step, step_result = cwe_updater_machine.step(State.start.value)
    return 'set the current state: {}'.format(current_step)


@app.route('/next')
def next():
    current_step, step_result = cwe_updater_machine.step()
    return 'set the current state: {}'.format(current_step)


def run_server():
    app.run(host=CWE_HOST, port=CWE_PORT, debug=True)

if __name__ == '__main__':
    run_server()
