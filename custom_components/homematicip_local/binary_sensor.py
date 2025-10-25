from __future__ import annotations

from functools import cached_property
from typing import TYPE_CHECKING, Any, cast

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import area_registry as ar
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from typing_extensions import override

from .const import DOMAIN
from .server.types.hmip_system import (
    DeviceBaseFunctionalChannel,
    DeviceOperationlockFunctionalChannel,
    DeviceSabotageFunctionalChannel,
    RuleMetaData,
    SecurityZoneGroup,
)

if TYPE_CHECKING:
    from .__init__ import HCUCoordinator


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    domain_bucket = cast(dict[str, dict[str, Any]], hass.data.get(DOMAIN, {}))  # pyright: ignore[reportExplicitAny]
    stored = domain_bucket.get(entry.entry_id, {})
    coordinator: HCUCoordinator = cast("HCUCoordinator", stored.get("coordinator"))

    known: set[str] = set()
    all_entities: list[BinarySensorEntity] = []

    def _discover() -> list[BinarySensorEntity]:
        body = coordinator.data
        devices = body["devices"]
        new_entities: list[BinarySensorEntity] = []
        for dev in devices.values():
            dev_id = dev["id"]
            label = dev["label"]
            channels = dev["functionalChannels"]

            # Battery low
            base = channels["0"]
            lb = base.get("lowBat")
            if isinstance(lb, bool):
                uid = f"battery:{dev_id}:0"
                if uid not in known:
                    name = f"{label or dev_id} Battery"
                    new_entities.append(
                        HCUBatteryLowBinarySensor(coordinator, dev_id, "0", name, uid)
                    )
                    known.add(uid)

            # Unreachable
            unreach = base.get("unreach")
            if isinstance(unreach, bool):
                uid = f"unreach:{dev_id}:0"
                if uid not in known:
                    name = f"{label or dev_id} Unreachable"
                    new_entities.append(
                        HCUUnreachableBinarySensor(coordinator, dev_id, "0", name, uid)
                    )
                    known.add(uid)
            for ch_key, ch in channels.items():
                uid_base = f"{dev_id}:{ch_key}"
                if ch["functionalChannelType"] == "SHUTTER_CONTACT_CHANNEL":
                    uid = f"window:{uid_base}"
                    if uid not in known:
                        name = f"{label or dev_id} window"
                        new_entities.append(
                            HCUWindowContactBinarySensor(
                                coordinator, dev_id, ch_key, name, uid
                            )
                        )
                        known.add(uid)

                # Motion detection
                if ch["functionalChannelType"] == "MOTION_DETECTION_CHANNEL":
                    uid = f"motion:{uid_base}"
                    if uid not in known:
                        name = f"{label or dev_id} motion"
                        new_entities.append(
                            HCUMotionBinarySensor(
                                coordinator, dev_id, ch_key, name, uid
                            )
                        )
                        known.add(uid)

                # Smoke detector alarms and chamber state
                if ch["functionalChannelType"] == "SMOKE_DETECTOR_CHANNEL":
                    # Smoke alarm (active unless IDLE_OFF)
                    uid = f"smoke_alarm:{uid_base}"
                    if uid not in known:
                        name = f"{label or dev_id} smoke alarm"
                        new_entities.append(
                            HCUSmokeAlarmBinarySensor(
                                coordinator, dev_id, ch_key, name, uid
                            )
                        )
                        known.add(uid)

                    # Chamber degraded (disabled by default)
                    uid2 = f"smoke_chamber_degraded:{uid_base}"
                    if uid2 not in known:
                        name2 = f"{label or dev_id} smoke chamber degraded"
                        new_entities.append(
                            HCUChamberDegradedBinarySensor(
                                coordinator, dev_id, ch_key, name2, uid2
                            )
                        )
                        known.add(uid2)

                # Power-up switch state
                sof = ch.get("supportedOptionalFeatures")
                if isinstance(sof, dict):
                    if (
                        cast(dict[str, bool], sof).get(
                            "IOptionalFeaturePowerUpSwitchState"
                        )
                        is True
                    ):
                        pus = ch.get("powerUpSwitchState")
                        if isinstance(pus, str):
                            uid3 = f"powerup:{uid_base}"
                            if uid3 not in known:
                                base_name = ch["label"] or (label + " Channel" + ch_key)
                                name3 = f"{base_name} power up state"
                                new_entities.append(
                                    HCUPowerUpSwitchBinarySensor(
                                        coordinator, dev_id, ch_key, name3, uid3
                                    )
                                )
                                known.add(uid3)

        # SECURITY_ZONE group entities
        groups = body["groups"]
        for gid, grp in groups.items():
            if grp.get("type") != "SECURITY_ZONE":
                continue
            glabel = grp["label"]
            base_uid = f"security_zone:{gid}"
            dev_name = f"Security Zone Group {glabel}"

            def _add(attribute: str, name: str):
                uid = f"{base_uid}:{attribute}"
                if uid in known:
                    return
                new_entities.append(
                    SecurityZoneBinarySensor(coordinator, gid, name, attribute, uid)
                )
                known.add(uid)

            _add("unreach", f"{dev_name} Unreachable")
            _add("lowBat", f"{dev_name} Battery Low")
            _add("dutyCycle", f"{dev_name} Duty Cycle")
            _add("silent", f"{dev_name} Silent")
            _add("sabotage", f"{dev_name} Sabotage")
            _add("windowState", f"{dev_name} Window State")

            uid = f"{base_uid}:window"
            if uid in known:
                continue
            glabel = grp["label"]
            name = f"Security Zone Group {glabel} active"
            new_entities.append(
                HCUSecurityZoneWindow(coordinator, gid, name, "windowState", uid)
            )
            known.add(uid)

        # Rule (Automation) active state
        rules = body["home"]["ruleMetaDatas"]
        for rid, rule in rules.items():
            label = rule["label"]
            uid = f"rule_active:{rid}"
            if uid in known:
                continue
            new_entities.append(HCURuleActiveBinarySensor(coordinator, rid, label))
            known.add(uid)

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
            if getattr(ent, "hass", None) is None:
                continue
            for attr in ("is_on",):
                try:
                    delattr(ent, attr)
                except Exception:
                    pass
            ent.async_write_ha_state()

    _ = coordinator.async_add_listener(_on_update)


class SecurityZoneBinarySensor(BinarySensorEntity):
    _coordinator: "HCUCoordinator"
    _group_id: str
    _attr_name: str | None
    _attr_unique_id: str | None
    _attribute: str

    def __init__(
        self,
        coordinator: "HCUCoordinator",
        group_id: str,
        name: str,
        attribute: str,
        uid: str,
    ) -> None:
        self._coordinator = coordinator
        self._group_id = group_id
        self._attr_name = name
        self._attr_unique_id = f"{DOMAIN}:{uid}"
        self._attribute = attribute

    def _get_group(self) -> SecurityZoneGroup:
        return cast(SecurityZoneGroup, self._coordinator.data["groups"][self._group_id])

    @cached_property
    @override
    def device_info(self) -> DeviceInfo:
        grp = self._get_group()
        group_label = grp["label"]
        return DeviceInfo(
            identifiers={(DOMAIN, f"group:{self._group_id}")},
            name=f"Security Zone Group {group_label}",
            manufacturer="Homematic IP",
            model="SECURITY_ZONE",
        )

    @cached_property
    @override
    def extra_state_attributes(self) -> dict[str, object] | None:
        grp = self._get_group()
        return {
            "group_id": self._group_id,
            "label": grp["label"],
            "silent": grp["silent"],
            "active": grp["active"],
        }

    @cached_property
    @override
    def is_on(self) -> bool | None:
        return cast(bool, self._get_group()[self._attribute])


class HCUSecurityZoneWindow(SecurityZoneBinarySensor):
    _coordinator: "HCUCoordinator"
    _group_id: str
    _attr_name: str | None
    _attr_unique_id: str | None
    _attribute: str
    _attr_device_class: BinarySensorDeviceClass | None = BinarySensorDeviceClass.WINDOW

    @cached_property
    @override
    def is_on(self) -> bool | None:
        ws = self._get_group()["windowState"]
        if isinstance(ws, str):
            return ws == "OPEN"
        return None


class _BaseHcuBinarySensor(BinarySensorEntity):
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

    def _get_channel(self):
        devices = self._coordinator.data["devices"]
        dev = devices[self._device_id]
        channels = dev["functionalChannels"]
        channel = channels[self._channel_key]
        return channel

    def _suggested_area_name(self) -> str | None:
        body = self._coordinator.data
        devices = body["devices"]
        dev = devices[self._device_id]
        channels = dev["functionalChannels"]
        channel = channels[self._channel_key]
        groups_list = channel["groups"]
        if not groups_list:
            return None
        groups_map = body["groups"]
        for gid in groups_list:
            group = groups_map[gid]
            if group["type"] == "META":
                label = group["label"]
                if label.strip():
                    return label.strip()
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

    @cached_property
    @override
    def extra_state_attributes(self) -> dict[str, object] | None:
        devices = self._coordinator.data["devices"]
        conn = devices[self._device_id]["connectionType"]
        data: dict[str, object] = {"device_id": self._device_id}
        data["connection_type"] = conn
        return data

    @cached_property
    @override
    def device_info(self) -> DeviceInfo:
        devices = self._coordinator.data["devices"]
        dev = devices[self._device_id]
        return DeviceInfo(
            identifiers={(DOMAIN, self._device_id)},
            manufacturer=dev["oem"],
            model=dev["modelType"],
            sw_version=dev["firmwareVersion"],
            name=dev["label"] or self._device_id,
            suggested_area=self._suggested_area_name(),
        )


class HCUWindowContactBinarySensor(_BaseHcuBinarySensor):
    _attr_device_class: BinarySensorDeviceClass | None = BinarySensorDeviceClass.WINDOW

    @cached_property
    @override
    def is_on(self) -> bool | None:
        dev = self._coordinator.data["devices"][self._device_id]
        channels = dev["functionalChannels"]
        ch = channels[self._channel_key]
        ws = ch.get("windowState")
        if isinstance(ws, str):
            return ws == "OPEN"
        return None


class HCUMotionBinarySensor(_BaseHcuBinarySensor):
    _attr_device_class: BinarySensorDeviceClass | None = BinarySensorDeviceClass.MOTION

    @cached_property
    @override
    def is_on(self) -> bool | None:
        dev = self._coordinator.data["devices"][self._device_id]
        channels = dev["functionalChannels"]
        ch = channels[self._channel_key]
        md = ch.get("motionDetected")
        if isinstance(md, bool):
            return md
        return None


class HCUSmokeAlarmBinarySensor(_BaseHcuBinarySensor):
    _attr_device_class: BinarySensorDeviceClass | None = BinarySensorDeviceClass.SMOKE

    @cached_property
    @override
    def is_on(self) -> bool | None:
        ch = self._get_channel()
        sdat = ch.get("smokeDetectorAlarmType")
        if isinstance(sdat, str):
            return sdat != "IDLE_OFF"
        return None


class HCUChamberDegradedBinarySensor(_BaseHcuBinarySensor):
    _attr_device_class: BinarySensorDeviceClass | None = BinarySensorDeviceClass.PROBLEM
    _attr_entity_registry_enabled_default: bool = False

    @cached_property
    @override
    def is_on(self) -> bool | None:
        ch = self._get_channel()
        val = ch.get("chamberDegraded")
        return bool(val) if isinstance(val, bool) else None


class HCUBatteryLowBinarySensor(_BaseHcuBinarySensor):
    _attr_device_class: BinarySensorDeviceClass | None = BinarySensorDeviceClass.BATTERY

    @cached_property
    @override
    def is_on(self) -> bool | None:
        dev = self._coordinator.data["devices"][self._device_id]
        channels = dev["functionalChannels"]
        base = cast(
            (
                DeviceBaseFunctionalChannel
                | DeviceOperationlockFunctionalChannel
                | DeviceSabotageFunctionalChannel
            ),
            channels["0"],
        )
        lb = base["lowBat"]
        if isinstance(lb, bool):
            return lb
        return None


class HCUUnreachableBinarySensor(_BaseHcuBinarySensor):
    _attr_device_class: BinarySensorDeviceClass | None = BinarySensorDeviceClass.PROBLEM
    _attr_entity_registry_enabled_default: bool = False

    @cached_property
    @override
    def is_on(self) -> bool | None:
        device = self._coordinator.data["devices"][self._device_id]
        base = device["functionalChannels"]["0"]
        unreach = base.get("unreach")
        if isinstance(unreach, bool):
            return unreach
        return None


class HCUPowerUpSwitchBinarySensor(_BaseHcuBinarySensor):
    """Binary sensor exposing the configured power-up switch behavior.

    True => PERMANENT_ON (turn on when power is restored)
    False => PERMANENT_OFF (stay off when power is restored)
    """

    _attr_device_class: BinarySensorDeviceClass | None = None

    @cached_property
    @override
    def is_on(self) -> bool | None:
        ch = self._get_channel()
        state = ch.get("powerUpSwitchState")
        if isinstance(state, str):
            if state == "PERMANENT_ON":
                return True
            if state == "PERMANENT_OFF":
                return False
        return None


class HCURuleActiveBinarySensor(BinarySensorEntity):
    """Binary sensor representing whether an Automation (rule) is active."""

    _coordinator: "HCUCoordinator"
    _rule_id: str
    _label: str
    _attr_unique_id: str | None
    _attr_name: str | None

    def __init__(self, coordinator: "HCUCoordinator", rule_id: str, label: str) -> None:
        self._coordinator = coordinator
        self._rule_id = rule_id
        self._label = label
        self._attr_name = label + "Active"
        self._attr_unique_id = f"{DOMAIN}:automation:{rule_id}:active"

    def _get_rule(self) -> RuleMetaData:
        return self._coordinator.data["home"]["ruleMetaDatas"][self._rule_id]

    @cached_property
    @override
    def is_on(self) -> bool | None:
        val = self._get_rule()["active"]
        return val

    @cached_property
    @override
    def extra_state_attributes(self) -> dict[str, object] | None:
        rule = self._get_rule()
        return {"rule_id": self._rule_id, "type": rule["type"]}

    @cached_property
    @override
    def device_info(self) -> DeviceInfo:
        name = self._label
        return DeviceInfo(
            identifiers={(DOMAIN, f"automation:{self._rule_id}")},
            manufacturer="Homematic IP Local",
            model="Automation rule",
            name=name,
        )
