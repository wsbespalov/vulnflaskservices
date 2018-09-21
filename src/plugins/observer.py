import os
import sys
import abc
import json
import redis
from datetime import datetime
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

from logger import LOGINFO_IF_ENABLED
from logger import LOGERR_IF_ENABLED
from utils import get_module_name

from caches import stats as stats_cache

from state import State
from state import decode as decode_state

MODULE_NAME = get_module_name(__file__)
SOURCE_MODULE = '[{0}] :: '.format(MODULE_NAME)


class Observer(metaclass=abc.ABCMeta):

    def __init__(self):
        self._subject = None
        self._observer_state = None

    @abc.abstractmethod
    def update(self, state):
        pass


class LogObserver(Observer):

    def __init__(self, source_module):
        self._source_module = source_module
        super(LogObserver, self).__init__()

    def update(self, state):
        self._observer_state = state
        if ' :: ' not in self._source_module:
            SM = '[{0}] :: '.format(self._source_module)
            LOGINFO_IF_ENABLED(SM, '[s] Set State as: [{}] with message: [{}]'.format(state, decode_state(state)))
        else:
            LOGINFO_IF_ENABLED(self._source_module, '[s] Set State as: [{}] with message: [{}]'.format(state, decode_state(state)))


class RedisObserver(Observer):
    """
    Create collection in Redis as: observer::source_module
        ex.: observer::[plg_cwe_updater]
    Set value as: decode_state(state)
        ex.: "idle"
    """

    def __init__(self, source_module):
        self._source_module = source_module
        self._collection_name = 'observer::{}'.format(self._source_module)
        self._cache = stats_cache
        super(RedisObserver, self).__init__()

    def update(self, state):
        self._observer_state = state
        try:
            return self._cache.set(self._collection_name, decode_state(state))
        except redis.ConnectionError as ce:
            LOGERR_IF_ENABLED(SOURCE_MODULE, '[e] Redis ConnectionError exception: {}'.format(ce))
            return 0


class RedisHistoryObserver(Observer):
    """
    Create collection in Redis as: observer::source_module
        ex.: observer::[plg_cwe_updater]
    RPush value as: decode_state(state)
        ex.: "idle"
    """
    def __init__(self, source_module):
        self._source_module = source_module
        self._cache = stats_cache
        self._collection_name = 'observer_history::{}'.format(self._source_module)
        super(RedisHistoryObserver, self).__init__()

    def update(self, state):
        def dt_converter(o):
            if isinstance(o, datetime):
                return o.__str__()
        self._observer_state = state
        message = {"state": decode_state(state), "ts": datetime.utcnow()}
        try:
            self._cache.rpush(self._collection_name, json.dumps(message, default=dt_converter))
        except redis.ConnectionError as ce:
            LOGERR_IF_ENABLED(SOURCE_MODULE, '[e] Redis ConnectionError exception: {}'.format(ce))
            return 0
