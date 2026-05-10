"""Connection coordinator for Sky Remote integration.

Manages the WebSocket connection lifecycle: connect, pair, bind,
reconnect on failure, and Wake-on-LAN.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import (
    DataUpdateCoordinator,
    UpdateFailed,
)

from .const import DEFAULT_PORT, DOMAIN
from .sky_remote_client import (
    SkyRemoteClient,
    SkyRemoteConnectionError,
    SkyRemoteError,
    is_box_reachable,
    send_wol,
)

_LOGGER = logging.getLogger(__name__)

RECONNECT_INTERVAL = timedelta(seconds=30)
MAX_RECONNECT_DELAY = 300  # 5 minutes


class SkyRemoteCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Coordinator that manages the Sky STB connection."""

    config_entry: ConfigEntry

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=RECONNECT_INTERVAL,
        )
        self.entry = entry
        self.host: str = entry.data["host"]
        self.port: int = entry.data.get("port", DEFAULT_PORT)
        self.mac: str | None = entry.data.get("mac")
        self.device_name: str = entry.data.get("name", "Sky Box")
        self.client = SkyRemoteClient(self.host, self.port)
        self._reconnect_attempts = 0

    @property
    def connected(self) -> bool:
        """Return True if the client is connected and bound."""
        return self.client.connected

    async def async_connect(self) -> None:
        """Establish connection: wake if needed, then connect + pair + bind."""
        woke_via_wol = False

        # Try WoL if we have a MAC and box is unreachable
        if self.mac and not await is_box_reachable(self.host, self.port):
            _LOGGER.info("Box unreachable, sending Wake-on-LAN to %s", self.mac)
            await self.hass.async_add_executor_job(send_wol, self.mac)
            woke_via_wol = True
            # Poll for wake-up (up to 30s)
            for _ in range(15):
                await asyncio.sleep(2)
                if await is_box_reachable(self.host, self.port):
                    _LOGGER.info("Box is now awake")
                    break
            else:
                raise SkyRemoteConnectionError(
                    f"Box at {self.host} did not wake up after WoL"
                )

        await self.client.connect_and_bind()
        self._reconnect_attempts = 0
        self.device_name = self.client.device_name or self.device_name

        # If woken via WoL, send Power to bring box out of standby
        if woke_via_wol:
            _LOGGER.info("Sending Power to wake box from standby")
            await asyncio.sleep(1)
            try:
                await self.client.send_key("Power")
            except SkyRemoteError:
                _LOGGER.warning("Post-WoL Power send failed")

        _LOGGER.info(
            "Connected to %s at %s:%s", self.device_name, self.host, self.port
        )

    async def async_disconnect(self) -> None:
        """Disconnect from the STB."""
        await self.client.disconnect()

    async def _async_update_data(self) -> dict[str, Any]:
        """Periodic update — reconnect if connection was lost."""
        if not self.client.connected:
            try:
                await self.async_connect()
            except SkyRemoteError as err:
                self._reconnect_attempts += 1
                delay = min(
                    30 * (2 ** self._reconnect_attempts), MAX_RECONNECT_DELAY
                )
                self.update_interval = timedelta(seconds=delay)
                raise UpdateFailed(
                    f"Connection failed (attempt {self._reconnect_attempts}): {err}"
                ) from err
        else:
            # Connection is healthy — reset to normal interval
            self.update_interval = RECONNECT_INTERVAL
            self._reconnect_attempts = 0

        return {
            "connected": self.client.connected,
            "device_name": self.device_name,
            "bind_id": self.client.bind_id,
        }

    async def async_send_key(self, key: str) -> dict:
        """Send a key command, reconnecting if necessary."""
        for attempt in range(2):
            if not self.client.connected:
                try:
                    await self.async_connect()
                except (SkyRemoteError, OSError) as err:
                    raise UpdateFailed(
                        f"Cannot send key — not connected: {err}"
                    ) from err
            try:
                return await self.client.send_key(key)
            except (SkyRemoteError, ConnectionResetError, OSError) as err:
                _LOGGER.warning(
                    "Key send failed (attempt %d): %s", attempt + 1, err
                )
                await self.client.disconnect()
                if attempt == 0:
                    continue  # retry once after reconnect
                raise UpdateFailed(f"Key send failed: {err}") from err
        raise UpdateFailed("Key send failed after retries")

    async def async_wake(self) -> None:
        """Send Wake-on-LAN and reconnect."""
        if self.mac:
            await self.hass.async_add_executor_job(send_wol, self.mac)
            _LOGGER.info("WoL sent to %s", self.mac)
        if not self.client.connected:
            await self.async_connect()
