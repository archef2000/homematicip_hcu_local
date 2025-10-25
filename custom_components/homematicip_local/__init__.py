from __future__ import annotations

from datetime import timedelta
from typing import Any, Callable, cast, override

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import DOMAIN, PLATFORMS
from .server.server import HCUController
from .server.types.hmip_system import SystemState


class HCUCoordinator(DataUpdateCoordinator[SystemState]):
    controller: HCUController
    _remove_controller_listener: Callable[[], None] | None

    def __init__(self, hass: HomeAssistant, controller: HCUController) -> None:
        super().__init__(
            hass,
            logger=controller.logger,
            name="HCU System State",
            update_interval=timedelta(seconds=30),
        )
        self.controller = controller
        self._remove_controller_listener = controller.add_state_listener(
            self._on_state_changed
        )

    async def _async_pull_and_update(self) -> None:
        def _get() -> SystemState | None:
            resp = self.controller.get_system_state()
            return resp

        data = await self.hass.async_add_executor_job(_get)
        if data:
            self.async_set_updated_data(data)
        else:
            self.logger.error("Failed to fetch system state from HCU")

    def _on_state_changed(self) -> None:
        _ = self.hass.loop.call_soon_threadsafe(
            self.hass.async_create_task, self._async_pull_and_update()
        )

    def close(self) -> None:
        cb = self._remove_controller_listener
        self._remove_controller_listener = None
        if cb is not None:
            try:
                cb()
            except Exception:
                pass

    @override
    async def _async_update_data(self):
        def _get():
            resp = self.controller.get_system_state()
            return resp

        return await self.hass.async_add_executor_job(_get)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    data = entry.data
    host = str(data.get("host"))
    activation_key = str(data.get("activation_key"))
    auth_token = str(data.get("auth_token"))
    client_id = cast(str, data.get("client_id", ""))

    controller = HCUController(host, activation_key, auth_token, client_id)
    controller.start()
    _ready = await hass.async_add_executor_job(controller.wait_until_ready, 5.0)

    coordinator = HCUCoordinator(hass, controller)
    await coordinator.async_config_entry_first_refresh()

    if DOMAIN not in hass.data:
        hass.data[DOMAIN] = {}
    hass.data[DOMAIN][entry.entry_id] = {
        "controller": controller,
        "coordinator": coordinator,
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    domain_bucket_obj = hass.data.get(DOMAIN)
    domain_bucket = cast(dict[str, dict[str, Any]], domain_bucket_obj)  # pyright: ignore[reportExplicitAny]
    stored = domain_bucket.pop(entry.entry_id)
    controller: HCUController | None = None
    coordinator: HCUCoordinator | None = None
    controller = (
        cast(HCUController, stored.get("controller"))
        if stored.get("controller")
        else None
    )
    coordinator = (
        cast(HCUCoordinator, stored.get("coordinator"))
        if stored.get("coordinator")
        else None
    )
    if coordinator:
        coordinator.close()
    if controller:
        await hass.async_add_executor_job(controller.stop)
    if DOMAIN in hass.data and not hass.data[DOMAIN]:
        _ = hass.data.pop(DOMAIN, None)
    return bool(unload_ok)
