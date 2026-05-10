"""Config flow for Sky Remote integration."""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import Any

import voluptuous as vol

try:
    from homeassistant.helpers.service_info.zeroconf import ZeroconfServiceInfo
except ImportError:
    from homeassistant.components.zeroconf import ZeroconfServiceInfo
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_HOST, CONF_PORT

from .const import DEFAULT_PORT, DOMAIN, MDNS_SERVICE_TYPE
from .sky_remote_client import (
    SkyRemoteClient,
    SkyRemoteAuthError,
    SkyRemoteConnectionError,
)

_LOGGER = logging.getLogger(__name__)

MANUAL_ENTRY = "manual"

MANUAL_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST): str,
        vol.Optional(CONF_PORT, default=DEFAULT_PORT): int,
    }
)


async def _try_connect(host: str, port: int) -> dict[str, Any]:
    """Test connection to the Sky box. Returns device info or raises."""
    client = SkyRemoteClient(host, port)
    try:
        await client.connect()
        pair_resp = await client.pair()
        pairingcode = pair_resp.get("pairingcode", "")
        stbnonce = pair_resp.get("stbnonce", "")
        await client.bind(pairingcode, stbnonce)
        return {
            "name": client.device_name or "Sky Box",
            "bind_id": client.bind_id,
        }
    finally:
        await client.disconnect()


async def _discover_sky_devices(timeout: float = 5.0) -> list[dict[str, Any]]:
    """Actively scan for Sky devices via mDNS (like the TUI does)."""
    try:
        from zeroconf import ServiceBrowser, Zeroconf
    except ImportError:
        _LOGGER.debug("zeroconf library not available for active scan")
        return []

    devices: list[dict[str, Any]] = []

    class Listener:
        def remove_service(self, zc, type_, name):
            pass

        def update_service(self, zc, type_, name):
            pass

        def add_service(self, zc, type_, name):
            try:
                info = zc.get_service_info(type_, name)
            except Exception:
                info = None
            if info:
                props = {}
                if info.properties:
                    for k, v in info.properties.items():
                        key = k.decode("utf-8", errors="replace") if isinstance(k, bytes) else str(k)
                        val = v.decode("utf-8", errors="replace") if isinstance(v, bytes) else str(v)
                        props[key] = val

                addresses = [socket.inet_ntoa(addr) for addr in info.addresses]
                if addresses:
                    devices.append({
                        "name": info.name.split(".")[0] if info.name else "Sky Box",
                        "host": addresses[0],
                        "port": info.port or DEFAULT_PORT,
                        "mac": props.get("wol_mac") or props.get("wowl_mac") or props.get("device_id"),
                        "properties": props,
                    })

    def _scan():
        zc = Zeroconf()
        listener = Listener()
        ServiceBrowser(zc, MDNS_SERVICE_TYPE, listener)
        import time
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if devices:
                break
            time.sleep(0.2)
        zc.close()

    await asyncio.get_event_loop().run_in_executor(None, _scan)
    return devices


class SkyRemoteConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Sky Remote."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize the config flow."""
        self._discovered_host: str | None = None
        self._discovered_port: int = DEFAULT_PORT
        self._discovered_name: str | None = None
        self._discovered_mac: str | None = None
        self._discovered_devices: list[dict[str, Any]] = []

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle user-initiated setup: scan then pick or enter manually."""
        _LOGGER.info("async_step_user called, user_input=%s", user_input)
        if user_input is not None:
            chosen = user_input.get("device")
            if chosen and chosen != MANUAL_ENTRY:
                # User selected a discovered device
                for dev in self._discovered_devices:
                    if dev["host"] == chosen:
                        self._discovered_host = dev["host"]
                        self._discovered_port = dev["port"]
                        self._discovered_name = dev["name"]
                        self._discovered_mac = dev.get("mac")
                        return await self._async_try_finish()
            # Fall through to manual entry
            return await self.async_step_manual()

        # First visit — run active mDNS scan
        self._discovered_devices = await _discover_sky_devices(timeout=5.0)

        if self._discovered_devices:
            # Build selection menu: discovered devices + manual option
            device_options = {
                dev["host"]: f"{dev['name']} ({dev['host']})"
                for dev in self._discovered_devices
            }
            device_options[MANUAL_ENTRY] = "Enter IP address manually…"

            return self.async_show_form(
                step_id="user",
                data_schema=vol.Schema(
                    {vol.Required("device"): vol.In(device_options)}
                ),
            )

        # No devices found — go straight to manual entry
        return await self.async_step_manual()

    async def async_step_manual(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle manual IP entry."""
        errors: dict[str, str] = {}

        if user_input is not None:
            host = user_input[CONF_HOST]
            port = user_input.get(CONF_PORT, DEFAULT_PORT)
            self._discovered_host = host
            self._discovered_port = port
            self._discovered_name = None
            self._discovered_mac = None
            return await self._async_try_finish(errors)

        return self.async_show_form(
            step_id="manual",
            data_schema=MANUAL_DATA_SCHEMA,
            errors=errors,
        )

    async def _async_try_finish(
        self, errors: dict[str, str] | None = None
    ) -> ConfigFlowResult:
        """Try connecting and create the config entry."""
        if errors is None:
            errors = {}

        host = self._discovered_host
        port = self._discovered_port

        try:
            _LOGGER.info("Attempting connection to %s:%s", host, port)
            info = await _try_connect(host, port)
            _LOGGER.info("Connection successful: %s", info)
        except SkyRemoteConnectionError as err:
            _LOGGER.error("Connection failed: %s", err)
            errors["base"] = "cannot_connect"
            return self.async_show_form(
                step_id="manual", data_schema=MANUAL_DATA_SCHEMA, errors=errors
            )
        except SkyRemoteAuthError as err:
            _LOGGER.error("Auth failed: %s", err)
            errors["base"] = "bind_failed"
            return self.async_show_form(
                step_id="manual", data_schema=MANUAL_DATA_SCHEMA, errors=errors
            )
        except Exception as err:  # noqa: BLE001
            _LOGGER.exception("Unexpected error during setup: %s", err)
            errors["base"] = "cannot_connect"
            return self.async_show_form(
                step_id="manual", data_schema=MANUAL_DATA_SCHEMA, errors=errors
            )

        await self.async_set_unique_id(host)
        self._abort_if_unique_id_configured()

        data = {
            CONF_HOST: host,
            CONF_PORT: port,
            "name": info["name"],
        }
        if self._discovered_mac:
            data["mac"] = self._discovered_mac

        return self.async_create_entry(title=info["name"], data=data)

    async def async_step_zeroconf(
        self, discovery_info: ZeroconfServiceInfo
    ) -> ConfigFlowResult:
        """Handle passive zeroconf/mDNS discovery from HA."""
        _LOGGER.info(
            "Zeroconf discovery: name=%s host=%s port=%s props=%s",
            discovery_info.name,
            discovery_info.host,
            discovery_info.port,
            discovery_info.properties,
        )

        # .host is the hostname string; .ip_address may be None
        host = discovery_info.host
        if discovery_info.ip_address:
            host = str(discovery_info.ip_address)
        port = discovery_info.port or DEFAULT_PORT
        name = discovery_info.name.split(".")[0] if discovery_info.name else "Sky Box"

        # Properties may be str or bytes depending on HA version
        props = discovery_info.properties or {}
        mac = None
        for key in ("wol_mac", "wowl_mac", "device_id"):
            val = props.get(key)
            if val is None:
                try:
                    val = props.get(key.encode())
                except Exception:
                    pass
            if val:
                mac = val.decode() if isinstance(val, bytes) else str(val)
                break

        await self.async_set_unique_id(host)
        self._abort_if_unique_id_configured()

        self._discovered_host = host
        self._discovered_port = port
        self._discovered_name = name
        self._discovered_mac = mac

        self.context["title_placeholders"] = {"name": name}
        return await self.async_step_zeroconf_confirm()

    async def async_step_zeroconf_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Confirm zeroconf discovery."""
        if user_input is not None:
            return await self._async_try_finish()

        return self.async_show_form(
            step_id="zeroconf_confirm",
            description_placeholders={
                "name": self._discovered_name,
                "host": self._discovered_host,
            },
        )
