from __future__ import annotations

from functools import cached_property
from typing import TYPE_CHECKING, Any, Callable, cast

from homeassistant.components.event import EventEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import area_registry as ar
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from typing_extensions import override

from .const import DOMAIN
from .server.types.hmip_system import FunctionalChannel, DeviceChannelEvent

if TYPE_CHECKING:
    from .__init__ import HCUCoordinator


DOORBELL_EVENT_TYPES: tuple[str, ...] = ("doorbell_pressed",)


class _BaseHcuEventEntity(EventEntity):
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

    def _get_channel(self) -> FunctionalChannel:
        devices = self._coordinator.data["devices"]
        dev = devices[self._device_id]
        return dev["functionalChannels"][self._channel_key]

    def _suggested_area_name(self) -> str | None:
        body = self._coordinator.data
        devices = body["devices"]
        dev = devices[self._device_id]
        channel = dev["functionalChannels"][self._channel_key]
        groups_list = channel.get("groups") or []
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

    def maybe_fire(self) -> None:
        """Check for event condition and fire event if detected."""
        pass

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


class HCUDoorBellEventEntity(_BaseHcuEventEntity):
    _attr_event_types: list[str] = ["doorbell_pressed"]
    _attr_entity_registry_enabled_default: bool = True
    _last_ts: int | None = None
    _last_ws: str | None = None

    def __init__(
        self,
        coordinator: "HCUCoordinator",
        device_id: str,
        channel_key: str,
        name: str,
        uid: str,
    ) -> None:
        super().__init__(coordinator, device_id, channel_key, name, uid)
        self._attr_icon: str | None = "mdi:bell-ring"
        self._unsub: Callable[[], None] = (
            coordinator.controller.add_device_event_listener(
                device_id, self._handle_device_event
            )
        )
        self.async_on_remove(self._unsub)

    def _handle_device_event(self, _ts: int, ev: DeviceChannelEvent) -> None:
        self._coordinator.logger.error("Doorbell event received: %s", ev)

    def _click_detected(self) -> bool:
        ch = self._get_channel()
        ts = ch.get("doorBellSensorEventTimestamp")
        if isinstance(ts, int):
            if self._last_ts is None or ts != self._last_ts:
                self._last_ts = ts
                return True
            return False
        ws = ch.get("windowState")
        if isinstance(ws, str):
            if self._last_ws != ws:
                self._last_ws = ws
                return ws == "OPEN"
            self._last_ws = ws
        return False

    @override
    def maybe_fire(self) -> None:
        if self._click_detected():
            self._trigger_event(
                "doorbell_pressed",
                {"device_id": self._device_id, "channel": self._channel_key},
            )


class HCUKeyChannelEventEntity(_BaseHcuEventEntity):
    """Expose SINGLE_KEY_CHANNEL events from DEVICE_CHANNEL_EVENT."""

    _attr_event_types: list[str] = [
        "key_press_long",
        "key_press_short",
        "key_press_long_start",
        "key_press_long_stop",
    ]
    _attr_entity_registry_enabled_default: bool = True

    def __init__(
        self,
        coordinator: "HCUCoordinator",
        device_id: str,
        channel_key: str,
        name: str,
        uid: str,
    ) -> None:
        super().__init__(coordinator, device_id, channel_key, name, uid)
        self._attr_icon: str | None = "mdi:gesture-tap-button"
        self._unsub: Callable[[], None] = (
            coordinator.controller.add_device_event_listener(
                device_id, self._handle_device_event
            )
        )
        self.async_on_remove(self._unsub)

    def _handle_device_event(self, ts: int, ev: DeviceChannelEvent) -> None:
        data = {
            "device_id": self._device_id,
            "functionalChannelIndex": ev["channelIndex"],
            "channelEventType": ev["channelEventType"],
            "channelIndex": ev["channelIndex"],
            "timestamp": ts,
        }
        event_type = ev["channelEventType"].lower()
        self._trigger_event(event_type, data)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    domain_bucket = cast(dict[str, dict[str, Any]], hass.data.get(DOMAIN, {}))  # pyright: ignore[reportExplicitAny]
    stored = domain_bucket.get(entry.entry_id, {})
    coordinator: HCUCoordinator = cast("HCUCoordinator", stored.get("coordinator"))

    known: set[str] = set()
    all_entities: list[_BaseHcuEventEntity] = []

    def _discover() -> list[_BaseHcuEventEntity]:
        body = coordinator.data
        devices = body["devices"]
        new_entities: list[_BaseHcuEventEntity] = []
        for dev in devices.values():
            dev_id = dev["id"]
            label = dev["label"]
            channels = dev["functionalChannels"]
            for ch_key, ch in channels.items():
                if ch["functionalChannelType"] == "MULTI_MODE_INPUT_CHANNEL":
                    uid = f"input:{dev_id}:{ch_key}"
                    if uid not in known:
                        name = f"{label or dev_id}"
                        new_entities.append(
                            HCUDoorBellEventEntity(
                                coordinator, dev_id, ch_key, name, uid
                            )
                        )
                        known.add(uid)
                elif ch["functionalChannelType"] == "SINGLE_KEY_CHANNEL":
                    uid = f"key:{dev_id}:{ch_key}"
                    if uid not in known:
                        name = f"{label or dev_id} Button {ch_key}"
                        new_entities.append(
                            HCUKeyChannelEventEntity(
                                coordinator, dev_id, ch_key, name, uid
                            )
                        )
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
            try:
                ent.maybe_fire()
            except Exception:
                pass

    _ = coordinator.async_add_listener(_on_update)

    for ent in all_entities:
        try:
            ent.maybe_fire()
        except Exception:
            pass
