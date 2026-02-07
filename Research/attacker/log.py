from prompt_toolkit.shortcuts import print_formatted_text
from prompt_toolkit.formatted_text import HTML
import html as html_escape

# Logging helpers for consistent output in the terminal
# We escape the message content but preserve intentional HTML tags in the message
def _safe_log(prefix: str, msg: str) -> None:
    """Log with HTML prefix, escaping content that's not meant to be HTML tags."""
    # Check if message already contains intentional ansi tags (like <ansigreen>)
    if '<ansi' in msg or '</ansi' in msg:
        # Message has intentional HTML tags, use as-is
        print_formatted_text(HTML(f"{prefix} {msg}"))
    else:
        # Escape HTML entities to prevent parsing errors
        print_formatted_text(HTML(f"{prefix} {html_escape.escape(str(msg))}"))

def log_info(msg): _safe_log("<ansiyellow>[ INFO ]</ansiyellow>", msg)
def log_error(msg): _safe_log("<ansired>[ ERR ]</ansired>", msg)
def log_success(msg): _safe_log("<ansigreen>[ SUCCESS ]</ansigreen>", msg)
def log_warn(msg): _safe_log("<ansiyellow>[ WARN ]</ansiyellow>", msg)