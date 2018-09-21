import enum

class State(enum.Enum):
    start = 1
    pending = 2
    downloading = 3
    parsing = 4
    caching_local = 5
    caching_global = 6
    write_database = 7
    finish = 8
    idle = 9
    undefined = 10


def decode(state):
    if state == State.start.value:
        return 'start'
    if state == State.pending.value:
        return 'pending'
    if state == State.downloading.value:
        return 'downloading'
    if state == State.parsing.value:
        return 'parsing'
    if state == State.caching_local.value:
        return 'caching_local'
    if state == State.caching_global.value:
        return 'caching_global'
    if state == State.finish.value:
        return 'finish'
    if state == State.idle.value:
        return 'idle'
    if state == State.undefined.value:
        return 'undefined'
    if state == State.write_database.value:
        return 'write_database'
    return 'undefined'


def encode(state):
    if state == 'start':
        return State.start.value
    if state == 'pending':
        return State.pending.value
    if state == 'downloading':
        return State.downloading.value
    if state == 'parsing':
        return State.parsing.value
    if state == 'caching_local':
        return State.caching_local.value
    if state == 'caching_global':
        return State.caching_global.value
    if state == 'finish':
        return State.finish.value
    if state == 'idle':
        return State.idle.value
    if state == 'write_database':
        return State.write_database.value
    if state == 'undefined':
        return State.undefined.value
    return State.undefined.value


def check(state):
    if state == State.start.value or \
        state == State.pending.value or \
        state == State.downloading.value or \
        state == State.parsing.value or \
        state == State.caching_local.value or \
        state == State.caching_global.value or \
        state == State.finish.value or \
        state == State.idle.value or \
        state == State.undefined.value or \
            state == State.write_database:
        return True
    return False


def step(state):
    """
    Start -> Pending -> Downloading -> Parsing -> Caching -> Caching -> Write Database -> Finish -> Idle --
    ^                                                                                                     |
    +--------[SCHEDULER]----------------------------------------------------------------------------------+

    Notes:
        Some states may be empty

    """
    if state is None:
        return State.start.value
    if state == State.start.value:
        return State.pending.value
    if state == State.pending.value:
        return State.downloading.value
    if state == State.downloading.value:
        return State.parsing.value
    if state == State.parsing.value:
        return State.caching_local.value
    if state == State.caching_local.value:
        return State.caching_global.value
    if state == State.caching_global.value:
        return State.write_database.value
    if state == State.write_database.value:
        return State.finish.value
    if state == State.finish.value:
        return State.idle.value
    if state == State.idle.value:
        return State.idle.value
    if state == State.undefined.value:
        return State.idle.value
    return State.idle.value
