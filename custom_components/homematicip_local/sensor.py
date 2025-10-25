from datetime import datetime, timezone
from functools import cached_property
from typing import TYPE_CHECKING, Any, cast

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import area_registry as ar
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from typing_extensions import override

from .const import DOMAIN
from .server.types.hmip_system import RuleMetaData

if TYPE_CHECKING:
    from .__init__ import HCUCoordinator


class _BaseDeviceSensor(SensorEntity):
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

    def _suggested_area_name(self) -> str | None:
        """Return room name from META group, if present for this channel."""
        body = self._coordinator.data
        device = body["devices"][self._device_id]
        channels = device["functionalChannels"]
        ch = channels[self._channel_key]
        groups_list = ch["groups"]
        if not groups_list:
            return None
        groups_map = body["groups"]
        for group_id in groups_list:
            group = groups_map[group_id]
            if group["type"] == "META":
                label = group["label"]
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

    def _get_channel(self):
        device = self._coordinator.data["devices"][self._device_id]
        channels = device["functionalChannels"]
        channel = channels[self._channel_key]
        return channel

    @cached_property
    @override
    def device_info(self) -> DeviceInfo:
        device = self._coordinator.data["devices"][self._device_id]
        return DeviceInfo(
            identifiers={(DOMAIN, self._device_id)},
            manufacturer=device["oem"],
            model=device["modelType"],
            sw_version=device["firmwareVersion"],
            name=device["label"] or self._device_id,
        )


class HCUDeviceTemperatureSensor(_BaseDeviceSensor):
    _attr_device_class: SensorDeviceClass | None = SensorDeviceClass.TEMPERATURE
    _attr_native_unit_of_measurement: str | None = "°C"

    @cached_property
    @override
    def native_value(self) -> float | None:
        ch = self._get_channel()
        v = ch.get("actualTemperature")
        return float(v) if isinstance(v, (int, float)) else None


class HCUDeviceSetpointTempSensor(_BaseDeviceSensor):
    _attr_device_class: SensorDeviceClass | None = SensorDeviceClass.TEMPERATURE
    _attr_native_unit_of_measurement: str | None = "°C"

    @cached_property
    @override
    def native_value(self) -> float | None:
        ch = self._get_channel()
        v = ch.get("setPointTemperature")
        return float(v) if isinstance(v, float) else None


class HCUDeviceHumiditySensor(_BaseDeviceSensor):
    _attr_device_class: SensorDeviceClass | None = SensorDeviceClass.HUMIDITY
    _attr_native_unit_of_measurement: str | None = "%"

    @cached_property
    @override
    def native_value(self) -> float | None:
        ch = self._get_channel()
        v = ch.get("humidity")
        return float(v) if isinstance(v, (int, float)) else None


class HCUDeviceIlluminationSensor(_BaseDeviceSensor):
    _attr_device_class: SensorDeviceClass | None = SensorDeviceClass.ILLUMINANCE
    _attr_native_unit_of_measurement: str | None = "lx"

    @cached_property
    @override
    def native_value(self) -> float | None:
        ch = self._get_channel()
        v = ch.get("illumination")
        return float(v) if isinstance(v, (int, float)) else None


class HCURssiDeviceSensor(_BaseDeviceSensor):
    _attr_device_class: SensorDeviceClass | None = SensorDeviceClass.SIGNAL_STRENGTH
    _attr_native_unit_of_measurement: str | None = "dBm"
    _attr_entity_registry_enabled_default: bool = False

    @cached_property
    @override
    def native_value(self) -> float | None:
        ch = self._get_channel()
        v = ch.get("rssiDeviceValue")
        return float(v) if isinstance(v, (int, float)) else None


class HCURssiPeerSensor(_BaseDeviceSensor):
    _attr_device_class: SensorDeviceClass | None = SensorDeviceClass.SIGNAL_STRENGTH
    _attr_native_unit_of_measurement: str | None = "dBm"
    _attr_entity_registry_enabled_default: bool = False

    @cached_property
    @override
    def native_value(self) -> float | None:
        ch = self._get_channel()
        v = ch.get("rssiPeerValue")
        return float(v) if isinstance(v, (int, float)) else None


class HCUAccessPointSignalBrightnessSensor(_BaseDeviceSensor):
    _attr_device_class: SensorDeviceClass | None = None
    _attr_native_unit_of_measurement: str | None = "%"

    @cached_property
    @override
    def native_value(self) -> float | None:
        ch = self._get_channel()
        v = ch.get("signalBrightness")
        if isinstance(v, (int, float)):
            return float(v) * 100.0
        return None


class HCUAccessPointDutyCycleLevelSensor(_BaseDeviceSensor):
    _attr_device_class: SensorDeviceClass | None = None
    _attr_native_unit_of_measurement: str | None = "%"
    _attr_entity_registry_enabled_default: bool = True

    @cached_property
    @override
    def native_value(self) -> float | None:
        ch = self._get_channel()
        v = ch.get("dutyCycleLevel")
        return float(v) if isinstance(v, (int, float)) else None


class HCUAccessPointCarrierSenseLevelSensor(_BaseDeviceSensor):
    _attr_device_class: SensorDeviceClass | None = None
    _attr_native_unit_of_measurement: str | None = "%"
    _attr_entity_registry_enabled_default: bool = True

    @cached_property
    @override
    def native_value(self) -> float | None:
        ch = self._get_channel()
        v = ch.get("carrierSenseLevel")
        return float(v) if isinstance(v, (int, float)) else None


class HCUSmokeDirtLevelSensor(_BaseDeviceSensor):
    """Dirt level for SMOKE_DETECTOR_CHANNEL; disabled by default."""

    _attr_device_class: SensorDeviceClass | None = None
    _attr_native_unit_of_measurement: str | None = "%"
    _attr_entity_registry_enabled_default: bool = False

    @cached_property
    @override
    def native_value(self) -> float | None:
        ch = self._get_channel()
        v = ch.get("dirtLevel")
        if isinstance(v, (int, float)):
            val = float(v)
            return val * 100.0
        return None


class HCUValvePositionSensor(_BaseDeviceSensor):
    """Valve position sensor for HEATING_THERMOSTAT_CHANNEL."""

    _attr_device_class: SensorDeviceClass | None = None
    _attr_native_unit_of_measurement: str | None = "%"

    @cached_property
    @override
    def native_value(self) -> float | None:
        ch = self._get_channel()
        v = ch.get("valvePosition")
        if isinstance(v, (int, float)):
            val = float(v)
            return val * 100.0
        return None


class HCUValveActualTemperatureSensor(_BaseDeviceSensor):
    """Current temperature for heating thermostats using valveActualTemperature."""

    _attr_device_class: SensorDeviceClass | None = SensorDeviceClass.TEMPERATURE
    _attr_native_unit_of_measurement: str | None = "°C"

    @cached_property
    @override
    def native_value(self) -> float | None:
        ch = self._get_channel()
        v = ch.get("valveActualTemperature")
        return float(v) if isinstance(v, (int, float)) else None


class HCUEnergyCounterSensor(_BaseDeviceSensor):
    """Energy counter sensor for switch measuring channels.

    Unit and accumulation depend on HmIP; we expose raw value and let users set units if needed.
    """

    _attr_device_class: SensorDeviceClass | None = SensorDeviceClass.ENERGY
    _attr_native_unit_of_measurement: str | None = "kWh"
    _attr_state_class: SensorStateClass | str | None = SensorStateClass.TOTAL_INCREASING

    @cached_property
    @override
    def native_value(self) -> float | None:
        ch = self._get_channel()
        v = ch.get("energyCounter")
        return float(v) if isinstance(v, (int, float)) else None


class HCUCurrentPowerConsumptionSensor(_BaseDeviceSensor):
    _attr_device_class: SensorDeviceClass | None = SensorDeviceClass.POWER
    _attr_native_unit_of_measurement: str | None = "W"

    @cached_property
    @override
    def native_value(self) -> float | None:
        ch = self._get_channel()
        v = ch.get("currentPowerConsumption")
        return float(v) if isinstance(v, (int, float)) else None


class HCURuleAutomationSensor(SensorEntity):
    """Sensor representing an Automation (ruleMetaData).

    State: executionCounterOfDay
    Attributes: active, lastExecutionTimestamp (raw and iso)
    Device: name set to rule label
    """

    _coordinator: "HCUCoordinator"
    _rule_id: str
    _label: str
    _attr_unique_id: str | None
    _attr_name: str | None

    def __init__(self, coordinator: "HCUCoordinator", rule_id: str, label: str) -> None:
        self._coordinator = coordinator
        self._rule_id = rule_id
        self._label = label
        self._attr_name = label + "Execution count today"
        self._attr_unique_id = f"{DOMAIN}:automation:{rule_id}:counter"

    def _get_rule(self) -> RuleMetaData:
        return self._coordinator.data["home"]["ruleMetaDatas"][self._rule_id]

    @cached_property
    @override
    def native_value(self) -> int | None:
        rule = self._get_rule()
        return rule["executionCounterOfDay"]

    @cached_property
    @override
    def extra_state_attributes(self) -> dict[str, object] | None:
        rule = self._get_rule()
        attrs: dict[str, object] = {"rule_id": self._rule_id, "type": rule["type"]}
        return attrs

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


class HCURuleLastExecutionTimestampSensor(SensorEntity):
    """Timestamp sensor for an Automation's lastExecutionTimestamp.

    State: datetime in UTC (if available)
    Device: grouped under the Automation device (name = rule label)
    """

    _coordinator: "HCUCoordinator"
    _rule_id: str
    _label: str
    _attr_unique_id: str | None
    _attr_name: str | None
    _attr_device_class: SensorDeviceClass | None = SensorDeviceClass.TIMESTAMP

    def __init__(self, coordinator: "HCUCoordinator", rule_id: str, label: str) -> None:
        self._coordinator = coordinator
        self._rule_id = rule_id
        self._label = label
        self._attr_name = label + "Last execution"
        self._attr_unique_id = f"{DOMAIN}:automation:{rule_id}:last_exec"

    def _get_rule(self) -> RuleMetaData:
        return self._coordinator.data["home"]["ruleMetaDatas"][self._rule_id]

    @cached_property
    @override
    def native_value(self):
        ts = self._get_rule()["lastExecutionTimestamp"]
        if ts is None:
            return None
        return datetime.fromtimestamp(int(ts) / 1000, tz=timezone.utc)

    @cached_property
    @override
    def extra_state_attributes(self) -> dict[str, object] | None:
        rule = self._get_rule()
        attrs: dict[str, object] = {"rule_id": self._rule_id, "type": rule["type"]}
        return attrs

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


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    domain_bucket = cast(dict[str, dict[str, Any]], hass.data.get(DOMAIN, {}))  # pyright: ignore[reportExplicitAny]
    stored = domain_bucket.get(entry.entry_id, {})
    coordinator: HCUCoordinator = cast("HCUCoordinator", stored.get("coordinator"))

    known: set[str] = set()
    all_entities: list[SensorEntity] = []

    def _discover() -> list[SensorEntity]:
        body = coordinator.data
        devices = body["devices"]

        new_entities: list[SensorEntity] = []
        for dev in devices.values():
            dev_type = dev["type"]
            dev_id = dev["id"]
            label = dev["label"]
            channels = dev["functionalChannels"]

            for ch_key, channel in channels.items():
                uid_base = f"{dev_id}:{ch_key}"

                # Actual temperature
                val = channel.get("actualTemperature")
                if isinstance(val, (int, float)):
                    uid = f"temp:{uid_base}"
                    if uid not in known:
                        name = f"{label or dev_id} Temperature"
                        new_entities.append(
                            HCUDeviceTemperatureSensor(
                                coordinator, dev_id, ch_key, name, uid
                            )
                        )
                        known.add(uid)

                # Set point temperature (thermostat)
                sp = channel.get("setPointTemperature")
                if isinstance(sp, (int, float)):
                    uid = f"setpoint:{uid_base}"
                    if uid not in known:
                        name = f"{label or dev_id} Set temperature"
                        new_entities.append(
                            HCUDeviceSetpointTempSensor(
                                coordinator, dev_id, ch_key, name, uid
                            )
                        )
                        known.add(uid)

                # Humidity
                h = channel.get("humidity")
                if isinstance(h, (int, float)):
                    uid = f"humidity:{uid_base}"
                    if uid not in known:
                        name = f"{label or dev_id} Humidity"
                        new_entities.append(
                            HCUDeviceHumiditySensor(
                                coordinator, dev_id, ch_key, name, uid
                            )
                        )
                        known.add(uid)

                # Illumination (light level)
                illum = channel.get("illumination")
                if isinstance(illum, (int, float)):
                    uid = f"illumination:{uid_base}"
                    if uid not in known:
                        name = f"{label or dev_id} Illuminance"
                        new_entities.append(
                            HCUDeviceIlluminationSensor(
                                coordinator, dev_id, ch_key, name, uid
                            )
                        )
                        known.add(uid)

                if (
                    channel["functionalChannelType"] == "DEVICE_SABOTAGE"
                    or channel["functionalChannelType"] == "DEVICE_BASE"
                    or channel["functionalChannelType"] == "DEVICE_OPERATIONLOCK"
                ):
                    sof = channel["supportedOptionalFeatures"]
                    if sof["IFeatureRssiValue"]:
                        # Device RSSI
                        uid = f"rssiDevice:{uid_base}"
                        if uid not in known:
                            name = f"{label or dev_id} RSSI device"
                            new_entities.append(
                                HCURssiDeviceSensor(
                                    coordinator, dev_id, ch_key, name, uid
                                )
                            )
                            known.add(uid)
                        # Peer RSSI
                        uidp = f"rssiPeer:{uid_base}"
                        if uidp not in known:
                            namep = f"{label or dev_id} RSSI peer"
                            new_entities.append(
                                HCURssiPeerSensor(
                                    coordinator, dev_id, ch_key, namep, uidp
                                )
                            )
                            known.add(uidp)

                # Access Point (and Home Control Access Point) controller channel extras
                if (
                    dev_type in {"ACCESS_POINT", "HOME_CONTROL_ACCESS_POINT"}
                    and channel.get("functionalChannelType")
                    == "ACCESS_CONTROLLER_CHANNEL"
                ):
                    # signalBrightness (0.0..1.0)
                    sb = channel.get("signalBrightness")
                    if isinstance(sb, float):
                        uid = f"ap_signal_brightness:{uid_base}"
                        if uid not in known:
                            name = f"{label or dev_id} signal brightness"
                            new_entities.append(
                                HCUAccessPointSignalBrightnessSensor(
                                    coordinator, dev_id, ch_key, name, uid
                                )
                            )
                            known.add(uid)

                    # dutyCycleLevel (0..100 %)
                    dcl = channel.get("dutyCycleLevel")
                    if isinstance(dcl, (int, float)):
                        uid = f"ap_duty_cycle:{uid_base}"
                        if uid not in known:
                            name = f"{label or dev_id} duty cycle level"
                            new_entities.append(
                                HCUAccessPointDutyCycleLevelSensor(
                                    coordinator, dev_id, ch_key, name, uid
                                )
                            )
                            known.add(uid)

                    # carrierSenseLevel (0..100 %)
                    csl = channel.get("carrierSenseLevel")
                    if isinstance(csl, (int, float)):
                        uid = f"ap_carrier_sense:{uid_base}"
                        if uid not in known:
                            name = f"{label or dev_id} carrier sense level"
                            new_entities.append(
                                HCUAccessPointCarrierSenseLevelSensor(
                                    coordinator, dev_id, ch_key, name, uid
                                )
                            )
                            known.add(uid)

                # Smoke detector dirt level (disabled by default)
                if channel["functionalChannelType"] == "SMOKE_DETECTOR_CHANNEL":
                    uid = f"smoke_dirt_level:{uid_base}"
                    if uid not in known:
                        name = f"{label or dev_id} smoke dirt level"
                        new_entities.append(
                            HCUSmokeDirtLevelSensor(
                                coordinator, dev_id, ch_key, name, uid
                            )
                        )
                        known.add(uid)

                if channel["functionalChannelType"] == "HEATING_THERMOSTAT_CHANNEL":
                    # Current temperature (valveActualTemperature)
                    uid = f"valve_actual_temp:{uid_base}"
                    if uid not in known:
                        name = f"{label or dev_id} Current temperature"
                        new_entities.append(
                            HCUValveActualTemperatureSensor(
                                coordinator, dev_id, ch_key, name, uid
                            )
                        )
                        known.add(uid)

                    # valvePosition
                    uid = f"valve_pos:{uid_base}"
                    if uid not in known:
                        name = f"{label or dev_id} valve position"
                        new_entities.append(
                            HCUValvePositionSensor(
                                coordinator, dev_id, ch_key, name, uid
                            )
                        )
                        known.add(uid)

                if channel["functionalChannelType"] == "SWITCH_MEASURING_CHANNEL":
                    # energyCounter
                    uid = f"energy_counter:{uid_base}"
                    if uid not in known:
                        name = f"{label or dev_id} energy counter"
                        new_entities.append(
                            HCUEnergyCounterSensor(
                                coordinator, dev_id, ch_key, name, uid
                            )
                        )
                        known.add(uid)

                    # currentPowerConsumption
                    uid2 = f"power_consumption:{uid_base}"
                    if uid2 not in known:
                        name2 = f"{label or dev_id} power consumption"
                        new_entities.append(
                            HCUCurrentPowerConsumptionSensor(
                                coordinator, dev_id, ch_key, name2, uid2
                            )
                        )
                        known.add(uid2)

        rules = body["home"]["ruleMetaDatas"]
        for rid, rule in rules.items():
            label = rule["label"]
            uid = f"rule_counter:{rid}"
            if uid not in known:
                new_entities.append(HCURuleAutomationSensor(coordinator, rid, label))
                known.add(uid)

            uid_ts = f"rule_last_exec:{rid}"
            if uid_ts not in known:
                new_entities.append(
                    HCURuleLastExecutionTimestampSensor(coordinator, rid, label)
                )
                known.add(uid_ts)

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
        # Invalidate cached properties and push state update for existing entities
        for ent in all_entities:
            if getattr(ent, "hass", None) is None:
                continue
            try:
                # Clear cached native_value so next read reflects latest coordinator data
                delattr(ent, "native_value")
            except Exception:
                pass
            try:
                # Also clear cached attributes in case they are dynamic
                delattr(ent, "extra_state_attributes")
            except Exception:
                pass
            ent.async_write_ha_state()

    _ = coordinator.async_add_listener(_on_update)
