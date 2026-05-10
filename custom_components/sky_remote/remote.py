"""Remote platform for Sky Remote integration."""

from __future__ import annotations

import logging
from typing import Any, Iterable

from homeassistant.components.remote import RemoteEntity, RemoteEntityFeature
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, VERIFIED_KEYS
from .coordinator import SkyRemoteCoordinator

_LOGGER = logging.getLogger(__name__)

# Activities map friendly names to sequences of key presses
ACTIVITIES: dict[str, list[str]] = {
    "home": ["Home"],
    "settings": ["Settings"],
    "search": ["Search"],
    "guide": ["Home", "ArrowDown", "Enter"],  # Navigate to guide from home
}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Sky Remote remote entity from a config entry."""
    coordinator: SkyRemoteCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([SkyRemote(coordinator, entry)])


class SkyRemote(CoordinatorEntity[SkyRemoteCoordinator], RemoteEntity):
    """Representation of a Sky set-top box as a remote."""

    _attr_has_entity_name = True
    _attr_name = "Remote"
    _attr_supported_features = RemoteEntityFeature.ACTIVITY

    def __init__(
        self, coordinator: SkyRemoteCoordinator, entry: ConfigEntry
    ) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{entry.data['host']}_remote"
        self._attr_device_info = {
            "identifiers": {(DOMAIN, entry.data["host"])},
            "name": coordinator.device_name,
            "manufacturer": "Sky",
            "model": "Set-Top Box",
        }
        self._attr_activity_list = list(ACTIVITIES.keys())
        self._is_on: bool = True

    @property
    def is_on(self) -> bool:
        """Return True if the remote is on."""
        return self.coordinator.connected and self._is_on

    async def async_turn_on(self, activity: str | None = None, **kwargs: Any) -> None:
        """Turn on the remote / start an activity."""
        await self.coordinator.async_wake()
        self._is_on = True

        if activity and activity in ACTIVITIES:
            for key in ACTIVITIES[activity]:
                await self.coordinator.async_send_key(key)

        self.async_write_ha_state()

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn off (standby)."""
        await self.coordinator.async_send_key("Power")
        self._is_on = False
        self.async_write_ha_state()

    async def async_send_command(
        self, command: Iterable[str], **kwargs: Any
    ) -> None:
        """Send commands to the Sky box.

        Each command should be a verified key name (e.g., "ArrowUp", "Enter").
        Supports num_repeats and delay_secs kwargs.

        Service call example:
          remote.send_command:
            entity_id: remote.sky_box_remote
            command:
              - ArrowUp
              - Enter
        """
        num_repeats = kwargs.get("num_repeats", 1)
        delay_secs = kwargs.get("delay_secs", 0.2)

        import asyncio

        for _ in range(num_repeats):
            for cmd in command:
                if cmd not in VERIFIED_KEYS:
                    _LOGGER.warning("Unknown key: %s (sending anyway)", cmd)
                await self.coordinator.async_send_key(cmd)
                if delay_secs > 0:
                    await asyncio.sleep(delay_secs)
