import logging


class ColoredFormatter(logging.Formatter):
    # Define colors for each logging level
    COLORS = {
        'DEBUG': '\033[94m',  # Blue
        'INFO': '\033[92m',  # Green
        'WARNING': '\033[93m',  # Yellow
        'ERROR': '\033[91m',  # Red
        'CRITICAL': '\033[95m',  # Magenta
    }
    RESET = '\033[0m'

    # def format(self, record):
    #     # Add the appropriate color based on the logging level
    #     log_color = self.COLORS.get(record.levelname, self.RESET)
    #     record.levelname = f"{log_color}{record.levelname}{self.RESET}"
    #     return super().format(record)
    def format(self, record):
        # Add the appropriate color based on the logging level
        log_color = self.COLORS.get(record.levelname, self.RESET)

        # Create the formatted log message with the color
        log_message = super().format(record)

        # Color the entire log message
        return f"{log_color}{log_message}{self.RESET}"


def setup_logger(name="NessusRider", level=logging.DEBUG):
    """
    Set up a centralized logger configuration with colored output.

    Parameters:
    - name (str): The name of the logger.
    - level (int): The logging level (default is DEBUG).

    Returns:
    - logging.Logger: Configured logger instance.
    """
    # Create a logger with the specified name
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Create a console handler with the same level
    ch = logging.StreamHandler()
    ch.setLevel(level)

    # Define a colored formatter
    formatter = ColoredFormatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)

    # Add the handler to the logger, avoiding duplicate handlers
    if not logger.hasHandlers():
        logger.addHandler(ch)

    return logger
