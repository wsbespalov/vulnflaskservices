import abc

from state import State
from state import step as step_state
from state import check as check_state


class Updater(object):

    def __init__(self):
        self.subject_state = State.idle.value

    def step(self, next=None):
        if next is None:
            self.subject_state = step_state(self.subject_state)
        else:
            if check_state(next):
                self.subject_state = next
            else:
                self.subject_state = State.idle.value

        return self.make_step_action()

    def make_step_action(self):
        if self.subject_state == State.start.value:
            return State.start.value, self.start()
        if self.subject_state == State.pending.value:
            return State.pending.value, self.pending()
        if self.subject_state == State.downloading.value:
            return State.downloading.value, self.downloading()
        if self.subject_state == State.parsing.value:
            return State.parsing.value, self.parsing()
        if self.subject_state == State.caching_local.value:
            return State.caching_local.value, self.caching_local()
        if self.subject_state == State.caching_global.value:
            return State.caching_global.value, self.caching_global()
        if self.subject_state == State.write_database.value:
            return State.write_database.value, self.write_database()
        if self.subject_state == State.idle.value:
            return State.idle.value, self.idle()
        if self.subject_state == State.finish.value:
            return State.finish.value, self.finish()
        if self.subject_state == State.undefined.value:
            return State.undefined.values, self.undefined()

    @abc.abstractmethod
    def start(self):
        pass

    @abc.abstractmethod
    def pending(self):
        pass

    @abc.abstractmethod
    def downloading(self):
        pass

    @abc.abstractmethod
    def parsing(self):
        pass

    @abc.abstractmethod
    def caching_local(self):
        pass

    @abc.abstractmethod
    def caching_global(self):
        pass

    @abc.abstractmethod
    def write_database(self):
        pass

    @abc.abstractmethod
    def idle(self):
        pass

    @abc.abstractmethod
    def finish(self):
        pass

    @abc.abstractmethod
    def undefined(self):
        pass
