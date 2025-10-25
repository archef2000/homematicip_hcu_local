from homeassistant.const import Platform

DOMAIN = "homematicip_local"
EVENT_KEY_CHANNEL = "hmip_key_channel_event"

PLATFORMS: list[Platform] = [
    Platform.SENSOR,
    Platform.BINARY_SENSOR,
    Platform.EVENT,
    Platform.LIGHT,
    Platform.CLIMATE,
    Platform.SWITCH,
]
