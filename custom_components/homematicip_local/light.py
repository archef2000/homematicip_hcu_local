from __future__ import annotations

from collections.abc import Mapping
from functools import cached_property, partial
from .server.types.hmip_system import (
    SwitchMeasuringSupportedOptionalFeatures,
)
from typing import TYPE_CHECKING, Any, cast

from homeassistant.components.light import (
    ATTR_BRIGHTNESS,
    ATTR_HS_COLOR,
    ATTR_EFFECT,
    LightEntity,
)
from homeassistant.components.light.const import ColorMode, LightEntityFeature
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import area_registry as ar
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from typing_extensions import override

from .server.types.hmip_system import UniversalLightFunctionalChannel

from .const import DOMAIN

if TYPE_CHECKING:
    from . import HCUCoordinator


class _BaseHCULight(LightEntity):
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
        groups_map = body["groups"]
        # First try: resolve META from channel-linked groups; also follow metaGroupId on non-META groups
        if groups_list:
            for gid in groups_list:
                g = groups_map[gid]
                if g["type"] == "META":
                    lbl = g["label"]
                    if lbl.strip():
                        return lbl.strip()
                else:
                    mgi = g["metaGroupId"]
                    if isinstance(mgi, str):
                        mg = groups_map[mgi]
                        mg_type = mg["type"]
                        if mg_type == "META":
                            mlbl = mg["label"]
                            if mlbl.strip():
                                return mlbl.strip()

        for gmeta in groups_map.values():
            gtype2 = gmeta["type"]
            if gtype2 != "META":
                continue
            chans2 = gmeta["channels"]
            for chd in chans2:
                did2 = chd.get("deviceId")
                if did2 == self._device_id:
                    glbl2 = gmeta.get("label")
                    if glbl2.strip():
                        return glbl2.strip()
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
        device = self._coordinator.data["devices"][self._device_id]
        channels = device["functionalChannels"]
        return channels[self._channel_key]

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


class HCUAccessPointNotificationLight(_BaseHCULight):
    _attr_supported_color_modes: set[ColorMode] | set[str] | None = {
        ColorMode.BRIGHTNESS
    }
    # Expose discrete simpleRGBColorState values as light effects
    _attr_supported_features: LightEntityFeature = LightEntityFeature.EFFECT

    # Allowed simpleRGBColorState values according to controller helper
    _ALLOWED_SIMPLE_COLORS: tuple[str, ...] = (
        "BLACK",
        "BLUE",
        "GREEN",
        "TURQUOISE",
        "RED",
        "PURPLE",
        "YELLOW",
        "WHITE",
    )

    @cached_property
    @override
    def color_mode(self) -> ColorMode | str | None:
        return ColorMode.BRIGHTNESS

    @cached_property
    @override
    def is_on(self) -> bool | None:
        ch = self._get_channel()
        val = ch.get("on")
        return bool(val) if isinstance(val, bool) else None

    @cached_property
    @override
    def brightness(self) -> int | None:
        ch = self._get_channel()
        lvl = ch.get("dimLevel")
        if isinstance(lvl, (int, float)):
            # dimLevel 0.0..1.0 -> 0..255
            b = max(0, min(255, int(round(float(lvl) * 255))))
            return b
        return None

    @cached_property
    @override
    def effect_list(self) -> list[str] | None:
        return list(self._ALLOWED_SIMPLE_COLORS)

    @cached_property
    @override
    def effect(self) -> str | None:
        ch = self._get_channel()
        val = ch.get("simpleRGBColorState")
        return str(val) if isinstance(val, str) else None

    @override
    async def async_turn_on(self, **kwargs: Mapping[str, object]) -> None:
        br: int | None = None
        v = kwargs.get(ATTR_BRIGHTNESS)
        if isinstance(v, int):
            br = v
        dim: float = (br / 255.0) if isinstance(br, (int, float)) else 1.0
        eff = kwargs.get(ATTR_EFFECT)
        color: str | None = None
        if isinstance(eff, str):
            up = eff.strip().upper()
            if up in self._ALLOWED_SIMPLE_COLORS:
                color = up
        ctrl = self._coordinator.controller
        func = partial(
            ctrl.set_notification_light,
            self._device_id,
            int(self._channel_key),
            dim_level=float(dim),
            **({"simple_rgb_color_state": color} if color else {}),
        )
        await self.hass.async_add_executor_job(func)

    @override
    async def async_turn_off(self, **kwargs: Mapping[str, object]) -> None:
        ctrl = self._coordinator.controller
        func = partial(
            ctrl.set_notification_light,
            self._device_id,
            int(self._channel_key),
            simple_rgb_color_state="BLACK",
            optical_signal_behaviour="OFF",
            dim_level=0.0,
        )
        await self.hass.async_add_executor_job(func)


class HCUDimmerLight(_BaseHCULight):
    """Light entity for any device channel with functionalChannelType DIMMER_CHANNEL."""

    _attr_supported_color_modes: set[ColorMode] | set[str] | None = {
        ColorMode.BRIGHTNESS
    }

    @cached_property
    @override
    def color_mode(self) -> ColorMode | str | None:
        return ColorMode.BRIGHTNESS

    def _min_on_level(self) -> float:
        ch = self._get_channel() or {}
        v = ch.get("onMinLevel")
        if isinstance(v, (int, float)) and 0.0 <= float(v) <= 1.0:
            return float(v)
        v2 = ch.get("dimLevelLowest")
        if isinstance(v2, (int, float)) and 0.0 <= float(v2) <= 1.0:
            return float(v2)
        return 0.05

    @cached_property
    @override
    def is_on(self) -> bool | None:
        ch = self._get_channel()
        val = ch.get("on")
        return val if isinstance(val, bool) else None

    @cached_property
    @override
    def brightness(self) -> int | None:
        ch = self._get_channel()
        lvl = ch.get("dimLevel")
        if isinstance(lvl, (int, float)):
            return max(0, min(255, int(round(float(lvl) * 255))))
        return None

    @override
    async def async_turn_on(self, **kwargs: Mapping[str, object]) -> None:
        v = kwargs.get(ATTR_BRIGHTNESS)
        if isinstance(v, int):
            dim = max(0.0, min(1.0, float(v) / 255.0))
        else:
            ch = self._get_channel()
            cur = ch.get("dimLevel")
            dim = (
                float(cur)
                if isinstance(cur, (int, float)) and cur > 0
                else self._min_on_level()
            )
        ctrl = self._coordinator.controller
        func = partial(
            ctrl.set_dimmer_level,
            self._device_id,
            int(self._channel_key),
            dim_level=float(dim),
        )
        await self.hass.async_add_executor_job(func)

    @override
    async def async_turn_off(self, **kwargs: Mapping[str, object]) -> None:
        ctrl = self._coordinator.controller
        func = partial(
            ctrl.set_switch_state,
            self._device_id,
            int(self._channel_key),
            on=False,
        )
        await self.hass.async_add_executor_job(func)


class HCUSwitchMeasuringLight(_BaseHCULight):
    """Treat SWITCH_MEASURING_CHANNEL as a light when light features are present."""

    _attr_supported_color_modes: set[ColorMode] | set[str] | None = {ColorMode.ONOFF}

    @cached_property
    @override
    def color_mode(self) -> ColorMode:
        return ColorMode.ONOFF

    @cached_property
    @override
    def is_on(self) -> bool | None:
        ch = self._get_channel()
        val = ch.get("on")
        return bool(val) if isinstance(val, bool) else None

    @cached_property
    @override
    def brightness(self) -> int | None:
        return None

    @cached_property
    @override
    def extra_state_attributes(self) -> dict[str, object] | None:
        base = super().extra_state_attributes or {"device_id": self._device_id}
        ch = self._get_channel() or {}
        ec = ch.get("energyCounter")
        if isinstance(ec, (int, float)):
            base["energy_counter"] = float(ec)
        pc = ch.get("currentPowerConsumption")
        if isinstance(pc, (int, float)):
            base["current_power_consumption"] = float(pc)
        return base

    @override
    async def async_turn_on(self, **kwargs: Mapping[str, object]) -> None:
        ctrl = self._coordinator.controller
        func = partial(
            ctrl.set_switch_state,
            self._device_id,
            int(self._channel_key),
            on=True,
        )
        await self.hass.async_add_executor_job(func)

    @override
    async def async_turn_off(self, **kwargs: Mapping[str, object]) -> None:
        ctrl = self._coordinator.controller
        func = partial(
            ctrl.set_switch_state,
            self._device_id,
            int(self._channel_key),
            on=False,
        )
        await self.hass.async_add_executor_job(func)


class HCUUniversalLight(_BaseHCULight):
    """Light entity for UNIVERSAL_LIGHT_CHANNEL (RGBW controller channels).

    Supports:
    - Brightness via dimLevel (0.0..1.0)
    - HS color when IOptionalFeatureHueSaturationValue is true
    - Color temperature in Kelvin when IOptionalFeatureColorTemperature is true
    """

    def __init__(
        self,
        coordinator: "HCUCoordinator",
        device_id: str,
        channel_key: str,
        name: str,
        uid: str,
    ) -> None:
        super().__init__(coordinator, device_id, channel_key, name, uid)
        # Determine supported color modes from channel features
        ch = self._get_channel()
        feats = ch["supportedOptionalFeatures"]
        support_hs = feats["IOptionalFeatureHueSaturationValue"]
        modes: set[ColorMode] = {ColorMode.HS} if support_hs else {ColorMode.BRIGHTNESS}
        self._attr_supported_color_modes: set[ColorMode] | set[str] | None = modes

    @override
    def _get_channel(self) -> UniversalLightFunctionalChannel:
        device = self._coordinator.data["devices"][self._device_id]
        channels = device["functionalChannels"]
        return cast(UniversalLightFunctionalChannel, channels[self._channel_key])

    def _min_on_level(self) -> float:
        ch = self._get_channel()
        v = ch.get("onMinLevel")
        if 0.0 <= float(v) <= 1.0:
            return float(v)
        return 0.05

    @cached_property
    @override
    def color_mode(self) -> ColorMode | str | None:
        ch = self._get_channel()
        feats = ch["supportedOptionalFeatures"]
        support_hs = feats["IOptionalFeatureHueSaturationValue"]
        if support_hs:
            return ColorMode.HS
        return ColorMode.BRIGHTNESS

    @cached_property
    @override
    def is_on(self) -> bool | None:
        ch = self._get_channel()
        val = ch.get("on")
        return bool(val) if isinstance(val, bool) else None

    @cached_property
    @override
    def brightness(self) -> int | None:
        ch = self._get_channel()
        lvl = ch.get("dimLevel")
        if isinstance(lvl, (int, float)):
            return max(0, min(255, int(round(float(lvl) * 255))))
        return None

    @cached_property
    @override
    def hs_color(self) -> tuple[float, float] | None:
        ch = self._get_channel()
        feats = ch["supportedOptionalFeatures"]
        if not bool(feats["IOptionalFeatureHueSaturationValue"]):
            return None
        hue = ch.get("hue")
        sat = ch.get("saturationLevel")
        if isinstance(hue, (int, float)) and isinstance(sat, (int, float)):
            return (float(hue), float(sat) * 100.0)
        return None

    @override
    async def async_turn_on(self, **kwargs: object) -> None:
        dim: float
        v = kwargs.get(ATTR_BRIGHTNESS)
        if isinstance(v, int):
            dim = max(0.0, min(1.0, float(v) / 255.0))
        else:
            ch = self._get_channel() or {}
            cur = ch.get("dimLevel")
            dim = (
                float(cur)
                if isinstance(cur, (int, float)) and cur > 0
                else self._min_on_level()
            )

        ctrl = self._coordinator.controller
        hs = cast(
            dict[int, float], kwargs.get(ATTR_HS_COLOR)
        )  # [0]Hue: 0-360; [1]Sat:0-100
        if isinstance(hs, (tuple, list)) and len(hs) >= 2:
            hue = int(hs[0])
            sat_pct = float(hs[1])
            func = partial(
                ctrl.set_hue_saturation_dim_level,
                self._device_id,
                int(self._channel_key),
                hue=hue,
                saturation_level=sat_pct / 100,
                dim_level=dim,
            )
            await self.hass.async_add_executor_job(func)
        else:
            func = partial(
                ctrl.set_dimmer_level,
                self._device_id,
                int(self._channel_key),
                dim_level=float(dim),
            )
            await self.hass.async_add_executor_job(func)

    @override
    async def async_turn_off(self, **kwargs: Mapping[str, object]) -> None:
        ctrl = self._coordinator.controller
        func = partial(
            ctrl.set_dimmer_level,
            self._device_id,
            int(self._channel_key),
            dim_level=0.0,
        )
        await self.hass.async_add_executor_job(func)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    domain_bucket = cast(dict[str, dict[str, Any]], hass.data.get(DOMAIN, {}))  # pyright: ignore[reportExplicitAny]
    stored = domain_bucket.get(entry.entry_id, {})
    coordinator: HCUCoordinator = cast("HCUCoordinator", stored.get("coordinator"))

    known: set[str] = set()
    all_entities: list[_BaseHCULight] = []

    def _discover() -> list[_BaseHCULight]:
        body = coordinator.data
        devices = body["devices"]
        new_entities: list[_BaseHCULight] = []
        for dev in devices.values():
            device_type = dev["type"]
            dev_id = dev["id"]
            label = dev["label"]
            channels = dev["functionalChannels"]

            for ch_key, ch in channels.items():
                if (
                    device_type == "ACCESS_POINT"
                    and ch["functionalChannelType"] == "NOTIFICATION_LIGHT_CHANNEL"
                ):
                    uid = f"ap_notify:{dev_id}:{ch_key}"
                    if uid not in known:
                        name = f"{label or dev_id} notification light"
                        new_entities.append(
                            HCUAccessPointNotificationLight(
                                coordinator, dev_id, ch_key, name, uid
                            )
                        )
                        known.add(uid)

                if ch["functionalChannelType"] == "DIMMER_CHANNEL":
                    uid = f"dimmer:{dev_id}:{ch_key}"
                    if uid not in known:
                        name = f"{label or dev_id}"
                        new_entities.append(
                            HCUDimmerLight(coordinator, dev_id, ch_key, name, uid)
                        )
                        known.add(uid)

                # Universal light (RGBW controller channels)
                if ch["functionalChannelType"] == "UNIVERSAL_LIGHT_CHANNEL":
                    ch_label = ch["label"]
                    name = ch_label or f"{label or dev_id} universal light {ch_key}"
                    uid = f"ulight:{dev_id}:{ch_key}"
                    if uid not in known:
                        role = ch.get("channelRole")
                        groups = ch.get("groups")
                        is_active_role = isinstance(role, str) and role.endswith(
                            "ACTUATOR"
                        )
                        has_group = len(groups) > 0
                        on_val = ch.get("on")
                        has_state = isinstance(on_val, bool)
                        if is_active_role or has_group or has_state:
                            new_entities.append(
                                HCUUniversalLight(
                                    coordinator, dev_id, ch_key, name, uid
                                )
                            )
                            known.add(uid)

                if ch["functionalChannelType"] == "SWITCH_MEASURING_CHANNEL":
                    sof: SwitchMeasuringSupportedOptionalFeatures = ch[
                        "supportedOptionalFeatures"
                    ]
                    is_light = False
                    if (
                        sof["IFeatureLightProfileActuatorChannel"] is True
                        or sof["IFeatureLightGroupActuatorChannel"] is True
                    ):
                        is_light = True

                    if is_light:
                        uid = f"switch_measuring_light:{dev_id}:{ch_key}"
                        if uid not in known:
                            name = f"{label or dev_id}"
                            if len(channels.keys()) > 2:
                                name += f" Channel {ch_key}"
                            new_entities.append(
                                HCUSwitchMeasuringLight(
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
            if getattr(ent, "hass", None) is None:
                continue
            for attr in ("is_on", "brightness", "hs_color", "color_mode", "effect"):
                try:
                    delattr(ent, attr)
                except Exception:
                    pass
            ent.async_write_ha_state()

    _ = coordinator.async_add_listener(_on_update)
