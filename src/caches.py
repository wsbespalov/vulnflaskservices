import os
import json
import redis

from utils import get_module_name
from settings import SETTINGS
from logger import LOGINFO_IF_ENABLED, LOGERR_IF_ENABLED

SOURCE_MODULE = '[{0}] :: '.format(get_module_name(__file__))

cache_local_settings = SETTINGS.get("cache", {})
cache_default_host = cache_local_settings.get("host", "localhost")
cache_default_port = cache_local_settings.get("port", 6379)
cache_default_db = cache_local_settings.get("db", 3)

store_local_settings = SETTINGS.get("store", {})
store_default_host = store_local_settings.get("host", "localhost")
store_default_port = store_local_settings.get("port", 6379)
store_default_db = store_local_settings.get("db", 2)

stats_local_settings = SETTINGS.get("stats", {})
stats_default_host = stats_local_settings.get("host", "localhost")
stats_default_port = stats_local_settings.get("port", 6379)
stats_defailt_db = stats_local_settings.get("db", 1)

queue_local_settings = SETTINGS.get("queue", {})
queue_default_host = queue_local_settings.get("host", "localhost")
queue_default_port = queue_local_settings.get("port", 6379)
queue_defailt_db = queue_local_settings.get("db", 0)

cache_host = os.environ.get("REDIS_HOST", cache_default_host)
cache_port = os.environ.get("REDIS_PORT", cache_default_port)
cache_db = os.environ.get("REDIS_CACHE_DB", cache_default_db)

queue_host = os.environ.get("REDIS_HOST", queue_default_host)
queue_port = os.environ.get("REDIS_PORT", queue_default_port)
queue_db = os.environ.get("REDIS_QUEUE_DB", queue_defailt_db)

stats_host = os.environ.get("REDIS_HOST", stats_default_host)
stats_port = os.environ.get("REDIS_PORT", stats_default_port)
stats_db = os.environ.get("REDIS_STATS_DB", stats_defailt_db)

store_host = os.environ.get("REDIS_HOST", store_default_host)
store_port = os.environ.get("REDIS_PORT", store_default_port)
store_db = os.environ.get("REDIS_CACHE_DB", store_default_db)

queue_charset = queue_local_settings.get("charset", "utf-8")
queue_decode_responses = queue_local_settings.get("decode_responses", True)

cache_charset = queue_charset
cache_decode_responses = queue_decode_responses

stats_charset = stats_local_settings.get("charset", "utf-8")
stats_decode_responses = stats_local_settings.get("decode_responses", True)

store_charset = store_local_settings.get("charset", "utf-8")
store_decode_responses = store_local_settings.get("decode_responses", True)

helpers_collection_name = SETTINGS.get("helpers_collection", "helpers_collection")


queue = redis.StrictRedis(
    host=queue_host,
    port=queue_port,
    db=queue_db,
    charset=queue_charset,
    decode_responses=queue_decode_responses
)

stats = redis.StrictRedis(
    host=stats_host,
    port=stats_port,
    db=stats_db,
    charset=stats_charset,
    decode_responses=stats_decode_responses
)

cache = redis.StrictRedis(
    host=cache_host,
    port=cache_port,
    db=cache_db,
    charset=cache_charset,
    decode_responses=cache_decode_responses
)

store = redis.StrictRedis(
    host=store_host,
    port=store_port,
    db=store_db,
    charset=store_charset,
    decode_responses=store_decode_responses
)

##############################################################################
# Redis
##############################################################################


def set_ping_counter(value):
    try:
        return stats.set('ping_counter', value)
    except Exception as ex:
        LOGERR_IF_ENABLED(SOURCE_MODULE, '[e] Got an exception with set ping counter value: {}'.format(ex))
        return False


def increment_ping_counter():
    try:
        return stats.incr('ping_counter')
    except Exception as ex:
        LOGERR_IF_ENABLED(SOURCE_MODULE, '[e] Got an exception with incr ping counter value: {}'.format(ex))
        return False


def get_ping_counter():
    try:
        return stats.get('ping_counter')
    except Exception as ex:
        LOGERR_IF_ENABLED(SOURCE_MODULE, '[e] Got an exception with get ping counter value: {}'.format(ex))
        return 0


def set_plugins_in_cache(plugins):
    try:
        return stats.set("run_plugins", json.dumps({"plugins": plugins}))
    except Exception as ex:
        LOGINFO_IF_ENABLED(SOURCE_MODULE, '[e] Get an exception when set plugins list in cache: {}'.format(ex))
    return False


def get_plugins_from_cache():
    try:
        plugins_from_cache = json.loads(stats.get("run_plugins"))
        return plugins_from_cache.get("plugins", [])
    except Exception as ex:
        LOGINFO_IF_ENABLED(SOURCE_MODULE, '[e] Get an exception when get plugins list from cache: {}'.format(ex))
    return {}


def drop_plugins_in_cache():
    try:
        stats.delete("run_plugins")
    except Exception as ex:
        LOGERR_IF_ENABLED(SOURCE_MODULE, '[e] Got an exception when drop collection with plugins in cache {}'.format(ex))


def set_plugin_job_flag(plugin_name, flag_value):
    try:
        return cache.set(plugin_name, flag_value)
    except Exception as ex:
        LOGINFO_IF_ENABLED(SOURCE_MODULE, '[e] Get an exception {} when set {} flag as {} in cache'.format(ex, plugin_name, flag_value))
        return False


def get_plugin_job_flag(plugin_name):
    try:
        get_flag = cache.get(plugin_name)
        return bool(get_flag) if get_flag is not None else False
    except Exception as ex:
        LOGINFO_IF_ENABLED(SOURCE_MODULE, '[e] Get an exception {} when get {} flag from cache'.format(ex, plugin_name))


def clear_helpers_collection():
    if not cache.exists(helpers_collection_name):
        return True
    try:
        cache.delete(helpers_collection_name)
    except Exception as ex:
        print("[e] Get an exception while load helpers from cache {}".format(ex))


def cache_push_helpers(element):
    try:
        cache.rpush(helpers_collection_name, element)
    except Exception as ex:
        print("[e] Get an exception while load helpers from cache {}".format(ex))


def push_helpers_collection(helpers):
    helpers = [helpers] if not isinstance(helpers, list) else helpers
    for helper in helpers:
        cache_push_helpers(helper)


def get_helpers_collection():
    helpers = []
    if not cache.exists(helpers_collection_name):
        return helpers
    try:
        helpers = cache.lrange(helpers_collection_name, 0, -1)
        if helpers is not None:
            if isinstance(helpers, list):
                return helpers
    except Exception as ex:
        print("[e] Get an exception while load helpers from cache {}".format(ex))
    return helpers


def check_redis_stats_connection():
    try:
        ping = stats.ping()
        if ping:
            return True
        else:
            LOGINFO_IF_ENABLED(SOURCE_MODULE, '[-] Redis is not available now for unknown reason')
            return False
    except Exception as ex:
        LOGERR_IF_ENABLED(SOURCE_MODULE, '[e] Got an exception with check redis (stats) connection with ping: {}'.format(ex))
    return False


def check_redis_queue_connection():
    try:
        ping = queue.ping()
        if ping:
            return True
        else:
            LOGINFO_IF_ENABLED(SOURCE_MODULE, '[-] Redis is not available now for unknown reason')
            return False
    except Exception as ex:
        LOGERR_IF_ENABLED(SOURCE_MODULE, '[e] Got an exception with check redis (queue) connection with ping: {}'.format(ex))
    return False


def check_redis_cache_connection():
    try:
        ping = cache.ping()
        if ping:
            return True
        else:
            LOGINFO_IF_ENABLED(SOURCE_MODULE, '[-] Redis is not available now for unknown reason')
            return False
    except Exception as ex:
        LOGERR_IF_ENABLED(SOURCE_MODULE, '[e] Got an exception with check redis (cache) connection with ping: {}'.format(ex))
    return False
