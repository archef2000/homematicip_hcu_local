from __future__ import annotations

from functools import cached_property
from typing import TYPE_CHECKING, Any, cast

from homeassistant.components.climate import ClimateEntity
from homeassistant.components.climate.const import ClimateEntityFeature, HVACMode
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import ATTR_TEMPERATURE, UnitOfTemperature
from homeassistant.core import HomeAssistant
from homeassistant.helpers import area_registry as ar
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from typing_extensions import override

from .const import DOMAIN
from .server.types.hmip_system import HeatingGroup

if TYPE_CHECKING:
    from .__init__ import HCUCoordinator


class HCUHeatingGroupClimate(ClimateEntity):
    """Climate entity driven by a HEATING group (no dedicated wall thermostat).

    Reads target/min/max/humidity from the group and tries to source current temperature
    from one of the member channels.
    """

    _coordinator: "HCUCoordinator"
    _group_id: str
    _attr_name: str | None
    _attr_unique_id: str | None
    _attr_temperature_unit: str = UnitOfTemperature.CELSIUS
    _attr_supported_features: ClimateEntityFeature = (
        ClimateEntityFeature.TARGET_TEMPERATURE
    )
    _attr_hvac_modes: list[HVACMode] = [HVACMode.AUTO, HVACMode.HEAT]

    def __init__(
        self, coordinator: "HCUCoordinator", group_id: str, name: str, uid: str
    ) -> None:
        self._coordinator = coordinator
        self._group_id = group_id
        self._attr_name = name
        self._attr_unique_id = f"{DOMAIN}:{uid}"

    def _groups_map(self):
        gm = self._coordinator.data["groups"]
        return gm

    def _group(self):
        g = cast(HeatingGroup, self._groups_map()[self._group_id])
        return g

    def _suggested_area_name(self) -> str | None:
        g = self._group()
        mgi = g["metaGroupId"]
        if isinstance(mgi, str):
            mg = self._groups_map()[mgi]
            if mg["type"] == "META":
                lbl = mg["label"]
                if lbl.strip():
                    return lbl.strip()

        lbl2 = g["label"]
        if lbl2.strip():
            return lbl2.strip()
        return None

    @override
    async def async_added_to_hass(self) -> None:
        area_name = self._suggested_area_name()
        if not area_name:
            return
        area_reg = ar.async_get(self.hass)
        dev_reg = dr.async_get(self.hass)
        area = area_reg.async_get_area_by_name(area_name)
        if area is None:
            area = area_reg.async_create(name=area_name)
        device = dev_reg.async_get_device(
            identifiers={(DOMAIN, f"group:{self._group_id}")}
        )
        if device and device.area_id != area.id:
            _ = dev_reg.async_update_device(device.id, area_id=area.id)

    @cached_property
    @override
    def device_info(self) -> DeviceInfo:
        g = self._group() or {}
        name = g["label"] or f"Heating {self._group_id}"
        return DeviceInfo(
            identifiers={(DOMAIN, f"group:{self._group_id}")},
            manufacturer="eQ-3",
            model="HmIP Heating Group",
            sw_version="",
            name=name,
            suggested_area=self._suggested_area_name(),
        )

    @cached_property
    @override
    def hvac_mode(self) -> HVACMode:
        g: HeatingGroup = self._group()
        if g["controlMode"] == "MANUAL":
            return HVACMode.HEAT
        return HVACMode.AUTO

    @cached_property
    @override
    def current_temperature(self) -> float | None:
        g = self._group()
        return g["valveActualTemperature"]

    @cached_property
    @override
    def target_temperature(self) -> float | None:
        g: HeatingGroup = self._group()
        return g["setPointTemperature"]

    @cached_property
    @override
    def current_humidity(self) -> int | None:
        g = self._group()
        return g["humidity"]

    @cached_property
    @override
    def min_temp(self) -> float:
        g = self._group()
        return g["minTemperature"]

    @cached_property
    @override
    def max_temp(self) -> float:
        g = self._group()
        return g["maxTemperature"]

    @cached_property
    @override
    def extra_state_attributes(self) -> dict[str, object] | None:
        g = self._group()
        data: dict[str, object] = {
            "group_id": self._group_id,
            "is_group": True,
            "party_mode": g["partyMode"],
        }
        return data

    @override
    async def async_set_temperature(self, **kwargs: object) -> None:
        temp_obj = kwargs.get(ATTR_TEMPERATURE)
        if not isinstance(temp_obj, (int, float)):
            return
        controller = self._coordinator.controller

        def _send() -> None:
            controller.set_heating_group_setpoint(self._group_id, float(temp_obj))

        await self.hass.async_add_executor_job(_send)
        self.async_write_ha_state()

    @override
    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        controller = self._coordinator.controller
        if hvac_mode == HVACMode.AUTO:
            controller.set_heating_control_mode(self._group_id, "AUTOMATIC")
        else:
            controller.set_heating_control_mode(self._group_id, "MANUAL")


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    domain_bucket = cast(dict[str, dict[str, Any]], hass.data.get(DOMAIN, {}))  # pyright: ignore[reportExplicitAny]
    stored = domain_bucket.get(entry.entry_id, {})
    coordinator: HCUCoordinator = cast("HCUCoordinator", stored.get("coordinator"))

    known: set[str] = set()
    all_entities: list[ClimateEntity] = []

    def _discover() -> list[ClimateEntity]:
        groups = coordinator.data["groups"]

        new_entities: list[ClimateEntity] = []

        for gid, g_map in groups.items():
            if g_map["type"] != "HEATING":
                continue
            uid = f"heating_group:{gid}"
            if uid in known:
                continue
            name = g_map["label"] or f"Heating {gid}"
            ent = HCUHeatingGroupClimate(coordinator, gid, name, uid)
            known.add(uid)
            new_entities.append(ent)
        return new_entities

    initial = _discover()
    if initial:
        async_add_entities(initial, True)
        all_entities.extend(initial)

    def _on_update() -> None:
        new = _discover()
        if new:
            async_add_entities(new)
            all_entities.extend(new)
        for ent in all_entities:
            for attr in (
                "hvac_mode",
                "current_temperature",
                "target_temperature",
                "current_humidity",
                "min_temp",
                "max_temp",
                "extra_state_attributes",
            ):
                try:
                    delattr(ent, attr)
                except Exception:
                    pass
            ent.async_write_ha_state()

    _ = coordinator.async_add_listener(_on_update)
