import logging
import os
import sys
import threading
import typing

import orjson
import structlog


class _LoggerCapsule:
    def __init__(self) -> None:
        self.logger: logging.Logger | None = None
        self.lock = threading.Lock()

    def get(self) -> logging.Logger | None:
        with self.lock:
            return self.logger

    def set(self, logger: logging.Logger | None) -> None:
        with self.lock:
            self.logger = logger


# by default, no logger is set and cydrogen will not emit any logs
_parent_logger: _LoggerCapsule = _LoggerCapsule()


def _drop_all_logs(logger, method_name: str, event_dict: structlog.typing.EventDict) -> structlog.typing.ProcessorReturnValue:  # noqa: ANN001, ARG001
    raise structlog.DropEvent


def dumps(obj, /, default=None, option=None) -> str:  # noqa: ANN001
    return orjson.dumps(obj, default=default, option=option).decode()


_processors: list[structlog.typing.Processor] = [
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
    structlog.processors.JSONRenderer(serializer=dumps),
]


def set_logger(logger: logging.Logger | None) -> None:
    """
    Set the logger to be used by cydrogen. If None is provided, cydrogen will not emit any logs.

    This method should be called by the host application using cydrogen during its initialization phase.

    Args:
        logger: The logger instance to be used by cydrogen, or None to disable logging.
    """
    _parent_logger.set(logger)


def set_own_logger(name: str = "cydrogen", level: int = logging.INFO) -> None:
    """
    Set a default logger for cydrogen that logs to stderr.

    This method should be called by the host application using cydrogen during its initialization phase,
    if it wants to use a default logger instead of providing its own.

    Args:
        level: The logging level to be set for the logger.

    """
    logger = logging.getLogger(name)
    handler = logging.StreamHandler(stream=sys.stderr)
    formatter = logging.Formatter("%(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(level)
    set_logger(logger)


class _BoundLoggerLazyProxy(structlog._config.BoundLoggerLazyProxy):  # noqa: SLF001
    """
    Subclass of structlog's BoundLoggerLazyProxy to be able to change the underlying logger at runtime.
    """

    def __init__(self) -> None:
        super().__init__(
            logger=_parent_logger,
            wrapper_class=None,
            processors=None,
            context_class=None,
            cache_logger_on_first_use=True,
            initial_values=None,
            logger_factory_args=None,
        )
        self._logger: _LoggerCapsule = _parent_logger

    def bind(self, **new_values: typing.Any) -> structlog.stdlib.BoundLogger:  # noqa: ANN401
        """
        Bind new values to the logger.

        When this method is called, the current underlying logger is retrieved from the capsule.
        The resulting BoundLogger will use the current logger at the time of this call.
        """
        _logger: typing.Any = self._logger.get()
        if _logger is None:
            return structlog.stdlib.BoundLogger(object(), processors=[_drop_all_logs], context={})
        logger = structlog.stdlib.BoundLogger(_logger, processors=_processors, context=dict(self._initial_values))
        return logger.bind(**new_values) if new_values else logger


_proxy = _BoundLoggerLazyProxy()


def get_logger(name: str = "cydrogen") -> _BoundLoggerLazyProxy:
    """
    Return the logger to be used within a cydrogen module.

    Returns:
        A structlog logger instance.
    """
    if os.environ.get("PYTEST_VERSION") is not None:
        # inside pytest runs, use the console renderer with DEBUG level for readability
        structlog.stdlib.recreate_defaults(log_level=logging.DEBUG)
        return structlog.get_logger(name)
    return _proxy
