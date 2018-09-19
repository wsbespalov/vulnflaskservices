import os
import sys
import abc
import json

sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

from logger import LOGINFO_IF_ENABLED
from logger import LOGERR_IF_ENABLED

from caches import stats as stats_cache

from state import State
from state import decode as decode_state

class Observer(metaclass=abc.ABCMeta):

    def __init__(self):
        self._subject = None
        self._observer_state = None

    @abc.abstractmethod
    def update(self, arg, msg=''):
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
        self._cache.set(self._collection_name, decode_state(state))


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
        self._observer_state = state
        self._cache.rpush(self._collection_name, decode_state(state))
