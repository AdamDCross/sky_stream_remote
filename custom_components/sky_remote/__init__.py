"""Sky Remote integration for Home Assistant.

Controls Sky set-top boxes over LAN via the RICS WebSocket protocol.
"""

from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .coordinator import SkyRemoteCoordinator

_LOGGER = logging.getLogger(__name__)


PLATFORMS: list[Platform] = [Platform.MEDIA_PLAYER, Platform.REMOTE]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Sky Remote from a config entry."""
    coordinator = SkyRemoteCoordinator(hass, entry)

    # Initial connection — will raise ConfigEntryNotReady on failure
    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        coordinator: SkyRemoteCoordinator = hass.data[DOMAIN].pop(entry.entry_id)
        await coordinator.async_disconnect()

    return unload_ok
