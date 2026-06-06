"""Constants for the Sky Remote integration."""

DOMAIN = "sky_remote"
DEFAULT_PORT = 8091
MDNS_SERVICE_TYPE = "_rdk-rics._tcp.local."

# Verified working key names (tested against real Sky STB)
# Source: VAa Dart enum in APK + brute-tested box extras
VERIFIED_KEYS: list[str] = [
    # Navigation & Selection
    "ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight",
    "Enter", "Backspace", "Dismiss", "Home",
    # Menu & Information
    "AccessMenu", "Info", "Option", "Search", "Settings",
    # Channel & Volume
    "ChannelUp", "ChannelDown",
    "VolumeUp", "VolumeDown", "VolumeMute",
    # Playback
    "MediaPlay", "MediaRecord", "MediaRewind", "MediaFastForward",
    # Power & Source
    "Power", "Source", "Plus",
    # Digits
    "Digit0", "Digit1", "Digit2", "Digit3", "Digit4",
    "Digit5", "Digit6", "Digit7", "Digit8", "Digit9",
    # Colour buttons
    "Red", "Green", "Yellow", "Blue",
]

# Auth token salt (from APK binary analysis)
AUTH_SALT = b"biT43y"
