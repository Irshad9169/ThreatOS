from __future__ import annotations
import logging
import logging.config
import os
import sys
import structlog

def configure_logging() -> None:
    """
    Configure structured JSON logging for production.
    In development: colourful human-readable output.
    In production: JSON lines for log aggregators (Splunk, Loki, ELK).
    """
    is_production = os.environ.get("APP_ENV","development") == "production"
    log_level     = os.environ.get("LOG_LEVEL", "INFO").upper()

    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
    ]

    if is_production:
        # JSON output — parseable by Splunk/Loki/ELK
        renderer = structlog.processors.JSONRenderer()
    else:
        # Human-readable coloured output for development
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    structlog.configure(
        processors=shared_processors + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
        foreign_pre_chain=shared_processors,
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers = [handler]
    root_logger.setLevel(getattr(logging, log_level, logging.INFO))

    # Silence noisy libraries
    for noisy in ["uvicorn.access","sqlalchemy.engine","httpx"]:
        logging.getLogger(noisy).setLevel(logging.WARNING)

def get_logger(name: str):
    """Get a structured logger instance."""
    return structlog.get_logger(name)
