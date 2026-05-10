"""Media player platform for Sky Remote integration."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.media_player import (
    MediaPlayerDeviceClass,
    MediaPlayerEntity,
    MediaPlayerEntityFeature,
    MediaPlayerState,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import SkyRemoteCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Sky Remote media player from a config entry."""
    coordinator: SkyRemoteCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([SkyMediaPlayer(coordinator, entry)])


class SkyMediaPlayer(CoordinatorEntity[SkyRemoteCoordinator], MediaPlayerEntity):
    """Representation of a Sky set-top box as a media player."""

    _attr_device_class = MediaPlayerDeviceClass.RECEIVER
    _attr_has_entity_name = True
    _attr_name = None  # Uses device name
    _attr_supported_features = (
        MediaPlayerEntityFeature.TURN_ON
        | MediaPlayerEntityFeature.TURN_OFF
        | MediaPlayerEntityFeature.VOLUME_STEP
        | MediaPlayerEntityFeature.VOLUME_MUTE
        | MediaPlayerEntityFeature.PLAY_MEDIA
        | MediaPlayerEntityFeature.PAUSE
        | MediaPlayerEntityFeature.PREVIOUS_TRACK
        | MediaPlayerEntityFeature.NEXT_TRACK
    )

    def __init__(
        self, coordinator: SkyRemoteCoordinator, entry: ConfigEntry
    ) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{entry.data['host']}_media_player"
        self._attr_device_info = {
            "identifiers": {(DOMAIN, entry.data["host"])},
            "name": coordinator.device_name,
            "manufacturer": "Sky",
            "model": "Set-Top Box",
        }
        self._is_on: bool = True

    @property
    def state(self) -> MediaPlayerState:
        """Return the state of the device."""
        if not self.coordinator.connected:
            return MediaPlayerState.OFF
        return MediaPlayerState.ON if self._is_on else MediaPlayerState.STANDBY

    async def _send(self, key: str) -> None:
        """Send a key and handle response."""
        await self.coordinator.async_send_key(key)

    async def async_turn_on(self) -> None:
        """Turn the box on (WoL + Power if needed)."""
        await self.coordinator.async_wake()
        self._is_on = True
        self.async_write_ha_state()

    async def async_turn_off(self) -> None:
        """Send power toggle to put box in standby."""
        await self._send("Power")
        self._is_on = False
        self.async_write_ha_state()

    async def async_volume_up(self) -> None:
        """Send volume up."""
        await self._send("VolumeUp")

    async def async_volume_down(self) -> None:
        """Send volume down."""
        await self._send("VolumeDown")

    async def async_mute_volume(self, mute: bool) -> None:
        """Send mute toggle."""
        await self._send("VolumeMute")

    async def async_media_play(self) -> None:
        """Send play."""
        await self._send("MediaPlay")

    async def async_media_pause(self) -> None:
        """Send play (acts as toggle on Sky)."""
        await self._send("MediaPlay")

    async def async_media_previous_track(self) -> None:
        """Channel down."""
        await self._send("ChannelDown")

    async def async_media_next_track(self) -> None:
        """Channel up."""
        await self._send("ChannelUp")

    async def async_play_media(
        self, media_type: str, media_id: str, **kwargs: Any
    ) -> None:
        """Play media by channel number.

        Sends each digit of the channel number as Digit0-Digit9 key presses.
        Usage: media_type="channel", media_id="101"
        """
        if media_type == "channel":
            for digit in str(media_id):
                if digit.isdigit():
                    await self._send(f"Digit{digit}")
