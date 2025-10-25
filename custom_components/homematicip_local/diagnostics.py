from typing import Any, cast

from homeassistant.components.diagnostics import async_redact_data  # pyright: ignore[reportUnknownVariableType]
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr

from .const import DOMAIN
from .server.server import HCUController
from .server.types.hmip_system import Device, SystemState


TO_REDACT: set[str] = {
    "activation_key",
    "auth_token",
    "client_id",
}


def _get_domain_bucket(hass: HomeAssistant, entry: ConfigEntry) -> dict[str, Any]:  # pyright: ignore[reportExplicitAny]
    domain_bucket = cast(dict[str, dict[str, Any]], hass.data.get(DOMAIN, {}))  # pyright: ignore[reportExplicitAny]
    return domain_bucket.get(entry.entry_id, {})


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
) -> dict[str, Any]:  # pyright: ignore[reportExplicitAny]
    stored = _get_domain_bucket(hass, entry)
    controller = cast(HCUController, stored.get("controller"))
    system_state: SystemState = controller.get_system_state()
    host = controller.ip

    return {
        "entry": async_redact_data(entry.as_dict(), TO_REDACT),
        "host": host,
        "system_state": system_state,
    }


async def async_get_device_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry, device: dr.DeviceEntry
) -> dict[str, Any]:  # pyright: ignore[reportExplicitAny]
    stored = _get_domain_bucket(hass, entry)
    controller = cast(HCUController, stored.get("controller"))
    system_state: SystemState = controller.get_system_state()
    devices = system_state.get("devices", {})

    dev_id: str | None = None
    for domain, ident in device.identifiers:
        if domain == DOMAIN:
            dev_id = ident
            break

    device_payload: Device | None = None
    if dev_id:
        device_payload = devices.get(dev_id)

    return {
        "entry": async_redact_data(entry.as_dict(), TO_REDACT),
        "device_registry": {
            "id": device.id,
            "name": device.name,
            "model": device.model,
            "manufacturer": device.manufacturer,
            "sw_version": device.sw_version,
        },
        "device_id": dev_id,
        "device": device_payload,
    }
