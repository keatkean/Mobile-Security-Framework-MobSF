import time
import logging

logger = logging.getLogger(__name__)

def check_accessibility_permission(self, package):
        """Check if APK has BIND_ACCESSIBILITY_SERVICE permission."""
        try:
            out = self.adb_command(['pm', 'dump', package], True)
            if out is None:
                logger.error('Error executing adb command to check permissions')
                return False
            return b'BIND_ACCESSIBILITY_SERVICE' in out
        except Exception:
            logger.exception('Error checking accessibility permission')
            return False

def execute_accessibility_commands(self):
    """Execute commands to open Accessibility settings and navigate."""
    logger.info('Opening Accessibility settings')
    self.adb_command(['shell', 'am', 'start', '-a', 'android.settings.ACCESSIBILITY_SETTINGS'])
    time.sleep(2)  # Wait for the settings activity to open
    logger.info('Navigating through Accessibility settings')
    # Simulate key events to navigate through the Accessibility settings
    commands = [
        'KEYCODE_TAB',
        'KEYCODE_ENTER',
        'KEYCODE_ENTER',
        'KEYCODE_TAB',
        'KEYCODE_ENTER',
    ]
    for command in commands:
        self.adb_command(['shell', 'input', 'keyevent', command])
        time.sleep(1)  # Add a delay between key events
