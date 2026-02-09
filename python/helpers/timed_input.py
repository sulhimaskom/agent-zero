import sys
from inputimeout import inputimeout, TimeoutOccurred
from python.helpers.constants import Timeouts

def timeout_input(prompt, timeout=Timeouts.INPUT_DEFAULT_TIMEOUT):
    try:
        if sys.platform != "win32": pass
        user_input = inputimeout(prompt=prompt, timeout=timeout)
        return user_input
    except TimeoutOccurred:
        return ""