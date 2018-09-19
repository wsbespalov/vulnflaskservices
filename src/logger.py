import logging
from settings import SETTINGS

logging.basicConfig(
    format='[%(asctime)s] :: %(message)s',
    level=logging.DEBUG)
logger = logging.getLogger(__file__)
logger.setLevel(logging.INFO)

enable_extra_logging = SETTINGS.get("enable_extra_logging", False)
enable_results_logging = SETTINGS.get("enable_results_logging", False)
enable_exception_logging = SETTINGS.get("enable_exception_logging", True)


def format_source(source_module):
    for _ in range(0, 40 - len(source_module)):
        source_module += '-'
    source_module += '>'
    return source_module


def LOGINFO_IF_ENABLED(source_module, message):
    if enable_extra_logging:
        logger.info(format_source(source_module) + message)


def LOGWARN_IF_ENABLED(source_module, message):
    if enable_extra_logging:
        logger.warning(format_source(source_module) + message)


def LOGERR_IF_ENABLED(source_module, message):
    if enable_exception_logging:
        logger.error(format_source(source_module) + message)


def LOGVAR_IF_ENABLED(source_module, message):
    if enable_results_logging:
        logger.info(format_source(source_module) + message)

