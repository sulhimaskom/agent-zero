import atexit
import html
import json
import logging
import os
import sys
from datetime import datetime

import webcolors

from . import files
from .constants import Colors


class PrintStyle:
    last_endline = True
    log_file_path = None

    # Structured logging configuration
    _structured_logging_enabled: bool = False
    _logger: logging.Logger | None = None
    _json_formatter: logging.Formatter | None = None

    # Mapping of PrintStyle methods to logging levels
    LOG_LEVELS = {
        "debug": logging.DEBUG,
        "standard": logging.INFO,
        "info": logging.INFO,
        "hint": logging.INFO,
        "success": logging.INFO,
        "warning": logging.WARNING,
        "error": logging.ERROR,
    }

    def __init__(
        self,
        bold=False,
        italic=False,
        underline=False,
        font_color="default",
        background_color="default",
        padding=False,
        log_only=False,
    ):
        self.bold = bold
        self.italic = italic
        self.underline = underline
        self.font_color = font_color
        self.background_color = background_color
        self.padding = padding
        self.padding_added = False  # Flag to track if padding was added
        self.log_only = log_only

        if PrintStyle.log_file_path is None:
            logs_dir = files.get_abs_path("logs")
            os.makedirs(logs_dir, exist_ok=True)
            log_filename = datetime.now().strftime("log_%Y%m%d_%H%M%S.html")
            PrintStyle.log_file_path = os.path.join(logs_dir, log_filename)
            with open(PrintStyle.log_file_path, "w") as f:
                f.write(
                    "<html><body style='background-color:black;font-family: Arial, Helvetica, sans-serif;'><pre>\n"
                )

    def _get_rgb_color_code(self, color, is_background=False):
        try:
            if color.startswith("#") and len(color) == 7:
                r = int(color[1:3], 16)
                g = int(color[3:5], 16)
                b = int(color[5:7], 16)
            else:
                rgb_color = webcolors.name_to_rgb(color)
                r, g, b = rgb_color.red, rgb_color.green, rgb_color.blue

            if is_background:
                return (
                    f"\033[48;2;{r};{g};{b}m",
                    f"background-color: rgb({r}, {g}, {b});",
                )
            else:
                return f"\033[38;2;{r};{g};{b}m", f"color: rgb({r}, {g}, {b});"
        except ValueError:
            return "", ""

    def _get_styled_text(self, text):
        start = ""
        end = "\033[0m"  # Reset ANSI code
        if self.bold:
            start += "\033[1m"
        if self.italic:
            start += "\033[3m"
        if self.underline:
            start += "\033[4m"
        font_color_code, _ = self._get_rgb_color_code(self.font_color)
        background_color_code, _ = self._get_rgb_color_code(self.background_color, True)
        start += font_color_code
        start += background_color_code
        return start + text + end

    def _get_html_styled_text(self, text):
        styles = []
        if self.bold:
            styles.append("font-weight: bold;")
        if self.italic:
            styles.append("font-style: italic;")
        if self.underline:
            styles.append("text-decoration: underline;")
        _, font_color_code = self._get_rgb_color_code(self.font_color)
        _, background_color_code = self._get_rgb_color_code(self.background_color, True)
        styles.append(font_color_code)
        styles.append(background_color_code)
        style_attr = " ".join(styles)
        escaped_text = html.escape(text).replace("\n", "<br>")  # Escape HTML special characters
        return f'<span style="{style_attr}">{escaped_text}</span>'

    def _add_padding_if_needed(self):
        if self.padding and not self.padding_added:
            if not self.log_only:
                pass  # Print an empty line for padding
            self._log_html("<br>")
            self.padding_added = True

    def _log_html(self, html):
        with open(PrintStyle.log_file_path, "a", encoding="utf-8") as f:  # type: ignore # add encoding='utf-8'
            f.write(html)

    @staticmethod
    def _close_html_log():
        if PrintStyle.log_file_path:
            with open(PrintStyle.log_file_path, "a") as f:
                f.write("</pre></body></html>")

    @staticmethod
    def _get_logger() -> logging.Logger:
        """Get or create the structured logging logger."""
        if PrintStyle._logger is None:
            PrintStyle._logger = logging.getLogger("agent_zero")
            PrintStyle._logger.setLevel(logging.DEBUG)
            # Add handler if not already present
            if not PrintStyle._logger.handlers:
                handler = logging.StreamHandler()
                handler.setLevel(logging.DEBUG)
                PrintStyle._logger.addHandler(handler)
        return PrintStyle._logger

    @staticmethod
    def _get_json_formatter() -> logging.Formatter:
        """Get or create the JSON formatter for structured logging."""
        if PrintStyle._json_formatter is None:
            PrintStyle._json_formatter = JsonFormatter()
        return PrintStyle._json_formatter

    @staticmethod
    def enable_structured_logging(enabled: bool = True, use_json: bool = False):
        """
        Enable or disable structured logging.

        Args:
            enabled: Whether to enable structured logging
            use_json: Whether to use JSON format (for log aggregators like Datadog, Splunk, ELK)
        """
        PrintStyle._structured_logging_enabled = enabled
        if enabled:
            logger = PrintStyle._get_logger()
            if use_json:
                for handler in logger.handlers:
                    handler.setFormatter(PrintStyle._get_json_formatter())

    @staticmethod
    def _log_structured(method_name: str, text: str):
        """Log to Python logging if structured logging is enabled."""
        if not PrintStyle._structured_logging_enabled:
            return

        logger = PrintStyle._get_logger()
        level = PrintStyle.LOG_LEVELS.get(method_name, logging.INFO)
        logger.log(level, text)

    def get(self, *args, sep=" ", **kwargs):
        text = sep.join(map(str, args))

        # Automatically mask secrets in all print output
        try:
            if not hasattr(self, "secrets_mgr"):
                from python.helpers.secrets import get_secrets_manager

                self.secrets_mgr = get_secrets_manager()
            text = self.secrets_mgr.mask_values(text)
        except Exception as e:
            # If masking fails, proceed without masking to avoid breaking functionality
            PrintStyle._get_logger().debug(f"Secret masking failed: {e}")
            pass

        return (
            text,
            self._get_styled_text(text),
            self._get_html_styled_text(text),
        )

    def print(self, *args, sep=" ", **kwargs):
        self._add_padding_if_needed()
        if not PrintStyle.last_endline:
            self._log_html("<br>")
        _plain_text, _styled_text, html_text = self.get(*args, sep=sep, **kwargs)
        if not self.log_only:
            pass
        self._log_html(html_text + "<br>\n")
        PrintStyle.last_endline = True

    def stream(self, *args, sep=" ", **kwargs):
        self._add_padding_if_needed()
        _plain_text, _styled_text, html_text = self.get(*args, sep=sep, **kwargs)
        if not self.log_only:
            pass
        self._log_html(html_text)
        PrintStyle.last_endline = False

    def is_last_line_empty(self):
        lines = sys.stdin.readlines()
        return bool(lines) and not lines[-1].strip()

    @staticmethod
    def standard(text: str):
        PrintStyle().print(text)
        PrintStyle._log_structured("standard", text)

    @staticmethod
    def hint(text: str):
        msg = "Hint: " + text
        PrintStyle(font_color=Colors.HINT, padding=True).print(msg)
        PrintStyle._log_structured("hint", msg)

    @staticmethod
    def info(text: str):
        msg = "Info: " + text
        PrintStyle(font_color=Colors.INFO, padding=True).print(msg)
        PrintStyle._log_structured("info", msg)

    @staticmethod
    def success(text: str):
        msg = "Success: " + text
        PrintStyle(font_color=Colors.SUCCESS, padding=True).print(msg)
        PrintStyle._log_structured("success", msg)

    @staticmethod
    def warning(text: str):
        msg = "Warning: " + text
        PrintStyle(font_color=Colors.WARNING, padding=True).print(msg)
        PrintStyle._log_structured("warning", msg)

    @staticmethod
    def debug(text: str):
        msg = "Debug: " + text
        PrintStyle(font_color=Colors.DEBUG, padding=True).print(msg)
        PrintStyle._log_structured("debug", msg)

    @staticmethod
    def error(text: str):
        msg = "Error: " + text
        PrintStyle(font_color="red", padding=True).print(msg)
        PrintStyle._log_structured("error", msg)


class JsonFormatter(logging.Formatter):
    """JSON formatter for structured logging to support log aggregators."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON for production log aggregation."""
        log_data = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add extra fields
        if hasattr(record, "extra"):
            log_data.update(record.extra)

        return json.dumps(log_data)


# Ensure HTML file is closed properly when the program exits
atexit.register(PrintStyle._close_html_log)
