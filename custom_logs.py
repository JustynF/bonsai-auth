import logging.handlers
import sys


class IncludeLevels(logging.Filter):
    """
    Filtering to only include specific log levels
    Based on Schore's post: https://stackoverflow.com/a/36338212
    Numeric log levels: https://docs.python.org/3/library/logging.html#logging-levels
    50: CRITICAL
    40: ERROR
    30: WARNING
    20: INFO
    10: DEBUG
    0: NOTSET
    """

    def __init__(self, minimum: int, maximum: int):
        self._minimum = minimum
        self._maximum = maximum
        logging.Filter.__init__(self)

    def filter(self, record: logging.LogRecord):
        if self._minimum <= record.levelno <= self._maximum:
            return True
        return False




log = logging.getLogger(str(__name__).split(".")[0])
formatter = logging.Formatter("%(asctime)s {%(filename)s:%(lineno)d} [%(levelname)s]: %(message)s")
# Levels up to WARNING are sent to STDOUT
stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setFormatter(formatter)
stdout_handler.addFilter(IncludeLevels(20, 30))
log.addHandler(stdout_handler)
# Levels ERROR and above are sent to STDERR
stderr_handler = logging.StreamHandler(sys.stdout)
stderr_handler.setFormatter(formatter)
stdout_handler.addFilter(IncludeLevels(40, 50))
log.addHandler(stderr_handler)
log.setLevel(logging.INFO)
