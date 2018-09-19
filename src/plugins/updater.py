from subject import Subject

from state import State
from state import step as step_state
from state import check as check_state


class Updater(Subject):

    def __init__(self):
        self.subject_state = State.idle.value
        super(Updater, self).__init__()

    def step(self, next=None):
        if next is None:
            step_state(self.subject_state)
        else:
            if check_state(next):
                self.subject_state = next
            else:
                self.subject_state = State.idle.value
