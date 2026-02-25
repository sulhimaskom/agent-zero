import secrets

from python.helpers import dotenv, runtime, settings
from python.helpers.print_style import PrintStyle

PrintStyle.standard("Preparing environment...")

try:
    runtime.initialize()

    # generate random root password if not set (for SSH)
    root_pass = dotenv.get_dotenv_value(dotenv.KEY_ROOT_PASSWORD)
    if not root_pass:
        root_pass = secrets.token_urlsafe(24)
        PrintStyle.standard("Changing root password...")
    settings.set_root_password(root_pass)

except Exception as e:
    PrintStyle.error(f"Error in preload: {e}")
