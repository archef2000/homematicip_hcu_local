from __future__ import annotations

from functools import cached_property, partial
from typing import TYPE_CHECKING, Any, cast, override

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import area_registry as ar
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .server.types.hmip_system import SecurityZoneGroup

from .const import DOMAIN

if TYPE_CHECKING:
    from . import HCUCoordinator


class _BaseHCUSwitch(SwitchEntity):
    _coordinator: "HCUCoordinator"
    _device_id: str
    _channel_key: str
    _attr_name: str | None
    _attr_unique_id: str | None

    def __init__(
        self,
        coordinator: "HCUCoordinator",
        device_id: str,
        channel_key: str,
        name: str,
        uid: str,
    ) -> None:
        self._coordinator = coordinator
        self._device_id = device_id
        self._channel_key = channel_key
        self._attr_name = name
        self._attr_unique_id = f"{DOMAIN}:{uid}"

    @property
    def hcu_device_id(self) -> str:
        """Public accessor for the underlying device id."""
        return self._device_id

    @property
    def hcu_suggested_area(self) -> str | None:
        """Public accessor for the suggested area name derived from META groups."""
        return self._suggested_area_name()

    def _suggested_area_name(self) -> str | None:
        body = self._coordinator.data
        device = body["devices"][self._device_id]
        channels = device["functionalChannels"]
        ch = channels[self._channel_key]
        groups_list = ch["groups"]
        groups_map = body["groups"]
        # First pass: resolve room from channel-linked groups; follow metaGroupId when needed
        if groups_list:
            for gid in groups_list:
                g = groups_map[gid]
                if g["type"] == "META":
                    label = g["label"]
                    if label.strip():
                        return label.strip()
                else:
                    mgi = g["metaGroupId"]
                    if isinstance(mgi, str):
                        mg = groups_map[mgi]
                        if mg["type"] == "META":
                            mlbl = mg["label"]
                            if mlbl.strip():
                                return mlbl.strip()

        for gmeta in groups_map.values():
            if gmeta["type"] != "META":
                continue
            chans2 = gmeta["channels"]
            for chd in chans2:
                did2 = chd["deviceId"]
                if did2 == self._device_id:
                    glbl2 = gmeta["label"]
                    if glbl2.strip():
                        return glbl2.strip()
                    break
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
        device = dev_reg.async_get_device(identifiers={(DOMAIN, self._device_id)})
        if device and device.area_id != area.id:
            _ = dev_reg.async_update_device(device.id, area_id=area.id)

    def _get_channel(self):
        dev = self._coordinator.data["devices"][self._device_id]
        channels = dev["functionalChannels"]
        ch = channels[self._channel_key]
        return ch

    @cached_property
    @override
    def device_info(self) -> DeviceInfo:
        dev = self._coordinator.data["devices"][self._device_id]
        return DeviceInfo(
            identifiers={(DOMAIN, self._device_id)},
            manufacturer=dev["oem"],
            model=dev["modelType"],
            sw_version=dev["firmwareVersion"],
            name=dev["label"] or self._device_id,
            suggested_area=self._suggested_area_name(),
        )

    @cached_property
    @override
    def extra_state_attributes(self) -> dict[str, object] | None:
        devices = self._coordinator.data["devices"]
        conn = devices[self._device_id]["connectionType"]
        data: dict[str, object] = {"device_id": self._device_id}
        data["connection_type"] = conn
        return data


class HCUSwitchChannel(_BaseHCUSwitch):
    @cached_property
    @override
    def is_on(self) -> bool | None:
        ch = self._get_channel()
        val = ch.get("on")
        return bool(val) if isinstance(val, bool) else None

    @override
    async def async_turn_on(self, **kwargs: object) -> None:
        ctrl = self._coordinator.controller
        fn = partial(
            ctrl.set_switch_state, self._device_id, int(self._channel_key), on=True
        )
        await self.hass.async_add_executor_job(fn)

    @override
    async def async_turn_off(self, **kwargs: object) -> None:
        ctrl = self._coordinator.controller
        fn = partial(
            ctrl.set_switch_state, self._device_id, int(self._channel_key), on=False
        )
        await self.hass.async_add_executor_job(fn)


class HCUSwitchMeasuringChannel(_BaseHCUSwitch):
    @cached_property
    @override
    def is_on(self) -> bool | None:
        ch = self._get_channel()
        val = ch.get("on")
        return bool(val) if isinstance(val, bool) else None

    @override
    async def async_turn_on(self, **kwargs: object) -> None:
        ctrl = self._coordinator.controller
        fn = partial(
            ctrl.set_switch_state, self._device_id, int(self._channel_key), on=True
        )
        await self.hass.async_add_executor_job(fn)

    @override
    async def async_turn_off(self, **kwargs: object) -> None:
        ctrl = self._coordinator.controller
        fn = partial(
            ctrl.set_switch_state, self._device_id, int(self._channel_key), on=False
        )
        await self.hass.async_add_executor_job(fn)


class HCUSecurityZoneActiveSwitch(SwitchEntity):
    _coordinator: "HCUCoordinator"
    _group_id: str
    _attr_name: str | None
    _attr_unique_id: str | None

    def __init__(
        self, coordinator: "HCUCoordinator", group_id: str, name: str, uid: str
    ) -> None:
        self._coordinator = coordinator
        self._group_id = group_id
        self._attr_name = name
        self._attr_unique_id = f"{DOMAIN}:{uid}"

    def _get_group(self) -> SecurityZoneGroup:
        return cast(SecurityZoneGroup, self._coordinator.data["groups"][self._group_id])

    @cached_property
    @override
    def device_info(self) -> DeviceInfo:
        grp = self._get_group()
        glabel = grp["label"]
        return DeviceInfo(
            identifiers={(DOMAIN, f"group:{self._group_id}")},
            manufacturer="Homematic IP",
            model="SECURITY_ZONE",
            name=f"Security Zone Group {glabel}",
        )

    @cached_property
    @override
    def extra_state_attributes(self) -> dict[str, object] | None:
        return {
            "group_id": self._group_id,
        }

    @cached_property
    @override
    def is_on(self) -> bool | None:
        grp = self._get_group()
        val = grp["active"]
        return val

    @override
    async def async_turn_on(self, **kwargs: object) -> None:
        grp = self._get_group()
        label = grp["label"]
        ctrl = self._coordinator.controller
        await self.hass.async_add_executor_job(
            ctrl.set_security_zone_active, label, True
        )

    @override
    async def async_turn_off(self, **kwargs: object) -> None:
        grp = self._get_group()
        label = grp["label"]
        ctrl = self._coordinator.controller
        await self.hass.async_add_executor_job(
            ctrl.set_security_zone_active, label, False
        )

    # Accessors used by update loop for area assignment compatibility
    @property
    def hcu_device_id(self) -> str:
        return f"group:{self._group_id}"

    @property
    def hcu_suggested_area(self) -> str | None:
        return None


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    domain_bucket = cast(dict[str, dict[str, Any]], hass.data.get(DOMAIN, {}))  # pyright: ignore[reportExplicitAny]
    stored = domain_bucket.get(entry.entry_id, {})
    coordinator: HCUCoordinator = cast("HCUCoordinator", stored.get("coordinator"))

    known: set[str] = set()
    all_entities: list[_BaseHCUSwitch] = []

    def _discover() -> list[SwitchEntity]:
        body = coordinator.data
        devices = body["devices"]
        new_entities: list[SwitchEntity] = []
        for dev in devices.values():
            dev_id = dev["id"]
            label = dev["label"]
            channels = dev["functionalChannels"]
            for ch_key, ch in channels.items():
                if ch["functionalChannelType"] == "SWITCH_CHANNEL":
                    uid = f"switch:{dev_id}:{ch_key}"
                    if uid in known:
                        continue
                    name = f"{label or dev_id}"
                    new_entities.append(
                        HCUSwitchChannel(coordinator, dev_id, ch_key, name, uid)
                    )
                    known.add(uid)

                if ch["functionalChannelType"] == "MULTI_MODE_INPUT_SWITCH_CHANNEL":
                    uid = f"multi_mode_switch:{dev_id}:{ch_key}"
                    if uid in known:
                        continue
                    suffix = "Channel" + ch_key
                    ch_label = ch["label"].strip()
                    name = f"{label or dev_id} {ch_label or suffix}"
                    new_entities.append(
                        HCUSwitchChannel(coordinator, dev_id, ch_key, name, uid)
                    )
                    known.add(uid)

                if ch["functionalChannelType"] == "SWITCH_MEASURING_CHANNEL":
                    sof = ch["supportedOptionalFeatures"]
                    is_light = False
                    if (
                        sof["IFeatureLightProfileActuatorChannel"] is True
                        or sof["IFeatureLightGroupActuatorChannel"] is True
                    ):
                        is_light = True
                    if is_light:
                        # Light platform will create it; skip here
                        continue
                    uid = f"switch_measuring:{dev_id}:{ch_key}"
                    if uid in known:
                        continue
                    role = ch.get("channelRole") or ""
                    suffix = role.replace("_", " ").lower() or "switch"
                    name = f"{label or dev_id} {suffix}"
                    new_entities.append(
                        HCUSwitchMeasuringChannel(
                            coordinator, dev_id, ch_key, name, uid
                        )
                    )
                    known.add(uid)

        groups = body["groups"]
        for gid, grp in groups.items():
            if grp["type"] != "SECURITY_ZONE":
                continue
            uid = f"security_zone_active:{gid}"
            if uid in known:
                continue
            glabel = grp["label"]
            name = f"Security Zone Group {glabel} active"
            new_entities.append(
                HCUSecurityZoneActiveSwitch(coordinator, gid, name, uid)
            )
            known.add(uid)

        return new_entities

    initial = _discover()
    if initial:
        async_add_entities(initial, True)
        all_entities.extend(cast(list[_BaseHCUSwitch], initial))

    def _on_update() -> None:
        new = _discover()
        if new:
            async_add_entities(new)
            all_entities.extend(cast(list[_BaseHCUSwitch], new))
        try:
            area_reg = ar.async_get(hass)
            dev_reg = dr.async_get(hass)
            for ent in all_entities:
                if getattr(ent, "hass", None) is None:
                    continue
                area_name = ent.hcu_suggested_area
                if not area_name:
                    continue
                area = area_reg.async_get_area_by_name(area_name)
                if area is None:
                    area = area_reg.async_create(name=area_name)
                device = dev_reg.async_get_device(
                    identifiers={(DOMAIN, ent.hcu_device_id)}
                )
                if device and device.area_id != area.id:
                    _ = dev_reg.async_update_device(device.id, area_id=area.id)
        except Exception:
            pass
        for ent in all_entities:
            if getattr(ent, "hass", None) is None:
                continue
            for attr in ("is_on", "extra_state_attributes"):
                try:
                    delattr(ent, attr)
                except Exception:
                    pass
            ent.async_write_ha_state()

    _ = coordinator.async_add_listener(_on_update)
