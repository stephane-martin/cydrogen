import logging
import os
import sys
import threading
import typing

import orjson
import structlog

try:
    import colorama  # type: ignore[import]
except ImportError:
    colorama = None

FORMAT = typing.Literal["json", "console", ""]
NAME = "cydrogen"


class _LoggerCapsule:
    def __init__(self) -> None:
        self.logger: logging.Logger | None = None
        self.fmt: FORMAT = "json"
        self.lock = threading.Lock()

    def get(self) -> tuple[logging.Logger | None, FORMAT]:
        with self.lock:
            return self.logger, self.fmt

    def set(self, logger: logging.Logger | None, fmt: FORMAT = "json") -> None:
        with self.lock:
            self.logger = logger
            self.fmt = fmt


# by default, no logger is set and cydrogen will not emit any logs
_logger_capsule: _LoggerCapsule = _LoggerCapsule()


def _drop_all_logs(logger, method_name: str, event_dict: structlog.typing.EventDict) -> structlog.typing.ProcessorReturnValue:  # noqa: ANN001, ARG001
    raise structlog.DropEvent


def _dumps(obj, /, default=None, option=None) -> str:  # noqa: ANN001
    return orjson.dumps(obj, default=default, option=option).decode()


_json_processors: list[structlog.typing.Processor] = [
    # If log level is too low, abort pipeline and throw away log entry.
    structlog.stdlib.filter_by_level,
    # Add the name of the logger to event dict.
    structlog.stdlib.add_logger_name,
    # Add log level to event dict.
    structlog.stdlib.add_log_level,
    # Perform %-style formatting.
    structlog.stdlib.PositionalArgumentsFormatter(),
    # Add a timestamp in ISO 8601 format.
    structlog.processors.TimeStamper(fmt="iso"),
    # If the "stack_info" key in the event dict is true, remove it and
    # render the current stack trace in the "stack" key.
    structlog.processors.StackInfoRenderer(),
    # If the "exc_info" key in the event dict is either true or a
    # sys.exc_info() tuple, remove "exc_info" and render the exception
    # with traceback into the "exception" key.
    structlog.processors.format_exc_info,
    # If some value is in bytes, decode it to a Unicode str.
    structlog.processors.UnicodeDecoder(),
    # Add callsite parameters.
    structlog.processors.CallsiteParameterAdder(
        {
            structlog.processors.CallsiteParameter.FILENAME,
            structlog.processors.CallsiteParameter.FUNC_NAME,
            structlog.processors.CallsiteParameter.LINENO,
        }
    ),
    # Render the final event dict as JSON.
    structlog.processors.JSONRenderer(serializer=_dumps),
]

_IS_WINDOWS = sys.platform == "win32"
_has_colors = not _IS_WINDOWS or colorama is not None

_colors = os.environ.get("NO_COLOR", "") == "" and (
    os.environ.get("FORCE_COLOR", "") != ""
    or (_has_colors and sys.stdout is not None and hasattr(sys.stdout, "isatty") and sys.stdout.isatty())
)

_console_processors: list[structlog.typing.Processor] = [
    structlog.stdlib.PositionalArgumentsFormatter(),
    structlog.contextvars.merge_contextvars,
    structlog.stdlib.add_log_level,
    structlog.stdlib.add_logger_name,
    structlog.stdlib.StackInfoRenderer(),
    structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S", utc=True),
    structlog.dev.ConsoleRenderer(colors=_colors),
]


def set_logger(logger: logging.Logger | None, fmt: FORMAT = "json") -> None:
    """
    Set the logger to be used by cydrogen. If None is provided, cydrogen will not emit any logs.

    This method should be called by the host application using cydrogen during its initialization phase.

    Args:
        logger: The logger instance to be used by cydrogen, or None to disable logging.
        fmt: The format in which logs should be emitted. Can be "json" or "console".
    """
    _logger_capsule.set(logger, fmt)


def set_own_logger(level: int = logging.INFO, fmt: FORMAT = "json") -> None:
    """
    Set a default logger for cydrogen that logs to stderr.

    This method should be called by the host application using cydrogen during its initialization phase,
    if it wants to use a default logger instead of providing its own.

    Args:
        level: The logging level to be set for the logger.
        fmt: The format in which logs should be emitted. Can be "json" or "console".

    """
    logger = logging.getLogger(NAME)
    handler = logging.StreamHandler(stream=sys.stderr)
    formatter = logging.Formatter("%(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(level)
    set_logger(logger, fmt)


_PYTEST = bool(os.environ.get("PYTEST_VERSION"))


if _PYTEST:
    # when running under pytest, set a default logger that logs to stderr at DEBUG level, using console format
    set_own_logger(level=logging.DEBUG, fmt="console")


class _BoundLoggerLazyProxy(structlog._config.BoundLoggerLazyProxy):  # noqa: SLF001
    """
    Subclass of structlog's BoundLoggerLazyProxy to be able to change the underlying logger at runtime.
    """

    def __init__(self) -> None:
        super().__init__(
            logger=_logger_capsule,
            wrapper_class=None,
            processors=None,
            context_class=None,
            cache_logger_on_first_use=True,
            initial_values=None,
            logger_factory_args=None,
        )
        self._logger_capsule: _LoggerCapsule = _logger_capsule

    def bind(self, **new_values: typing.Any) -> structlog.stdlib.BoundLogger:  # noqa: ANN401
        """
        Bind new values to the logger.

        When this method is called, the current underlying logger is retrieved from the capsule.
        The resulting BoundLogger will use the current logger at the time of this call.
        """
        parent_logger, fmt = self._logger_capsule.get()
        if parent_logger is None or not fmt:
            # no parent logger set, drop all logs
            return structlog.stdlib.BoundLogger(object(), processors=[_drop_all_logs], context={})
        processors = _console_processors if fmt == "console" else _json_processors
        blogger = structlog.stdlib.BoundLogger(parent_logger, processors=processors, context={})
        return blogger.bind(**new_values) if new_values else blogger


_proxy: typing.Any = _BoundLoggerLazyProxy()


def get_logger() -> structlog.stdlib.BoundLogger:
    """
    Return the logger to be used within a cydrogen module.

    Returns:
        A structlog logger instance.
    """
    return _proxy
