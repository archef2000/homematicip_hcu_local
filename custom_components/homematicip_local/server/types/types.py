from typing import Literal, TypeAlias


# 6.6 Types

# 6.6.1. AckType
AckType: TypeAlias = Literal[
    "NO",  # User acknowledged the message with NO. Applicable for user messages with BehaviorType 'ACKNOWLEDGEABLE_BY_YES_NO'.
    "OK",  # User acknowledged the message with OK. Applicable for user messages with BehaviorType 'ACKNOWLEDGEABLE_BY_OK'.
    "YES",  # User acknowledged the message with YES. Applicable for user messages with BehaviorType 'ACKNOWLEDGEABLE_BY_YES_NO'.
]
"""Acknowledgement type of a user message created by a plugin to be shown in the Homematic IP smartphone app."""

# 6.6.2. BehaviorType
BehaviorType: TypeAlias = Literal[
    "ACKNOWLEDGEABLE_BY_OK",
    "ACKNOWLEDGEABLE_BY_YES_NO",
    "DISMISSIBLE",
    "NOT_DISMISSIBLE",
]
"""Behavior type of a user message created by a plugin to be shown in the Homematic IP smartphone app. Used by app to enable the user to dismiss or acknowledge the message, or to prevent the user from dismissing it."""

# 6.6.3. ClimateOperationType
ClimateOperationType: TypeAlias = Literal["AUTO", "COOLING", "HEATING"]
"""Enumerated type of climate operation modes. Used by plugin devices supporting the ClimateOperationMode feature."""

# 6.6.4. ConfigUpdateResponseStatus
ConfigUpdateResponseStatus: TypeAlias = Literal["APPLIED", "FAILED", "PENDING"]
"""Describes the result or intermediate status of a plugin configuration update that was triggered by a HCUweb user by updating the plugin configuration and saving the changes."""

# 6.6.5. DeviceType
DeviceType: TypeAlias = Literal[
    "BATTERY",
    "CLIMATE_SENSOR",
    "CONTACT_SENSOR",
    "ENERGY_METER",
    "EV_CHARGER",
    "GRID_CONNECTION_POINT",
    "HEAT_PUMP",
    "HVAC",
    "INVERTER",
    "LIGHT",
    "OCCUPANCY_SENSOR",
    "PARTICULATE_MATTER_SENSOR",
    "SMOKE_ALARM",
    "SWITCH",
    "SWITCH_INPUT",
    "THERMOSTAT",
    "VEHICLE",
    "WATER_SENSOR",
    "WINDOW_COVERING",
]
"""Each type supports a set of required and/or optional features."""

# 6.6.6. Feature
Feature = Literal[
    "actualTemperature",
    "batteryState",
    "climateOperationMode",
    "co2",
    "color",
    "colorTemperature",
    "contactSensorState",
    "coolingTemperatureOffset",
    "currentPower",
    "dimming",
    "energyCounter",
    "heatingTemperatureOffset",
    "hotWaterBoost",
    "humidity",
    "illumination",
    "maintenance",
    "moistureDetected",
    "onTime",
    "particulateMassConcentrationOne",
    "particulateMassTen",
    "particulateMassTwoPointFive",
    "particulateTypicalSize",
    "presenceDetected",
    "presenceMode",
    "rainCount",
    "raining",
    "setPointTemperature",
    "shutterDirection",
    "shutterLevel",
    "slatsLevel",
    "smokeAlarm",
    "storm",
    "sunshine",
    "sunshineDuration",
    "supplyTemperature",
    "switchState",
    "vehicleRange",
    "waterlevelDetected",
    "windDirection",
    "windSpeed",
]
"""Feature types for plugin devices to be included in the Homematic IP system."""

# 6.6.7. MessageCategory
MessageCategory = Literal["ERROR", "INFO", "WARN"]
"""Category of a user message created by a plugin to be shown in the Homematic IP smartphone app. Used by the app to show the message with applicable color and icon."""

# 6.6.8. PluginMessageType
PluginMessageType = Literal[
    "CONFIG_TEMPLATE_REQUEST",
    "CONFIG_TEMPLATE_RESPONSE",
    "CONFIG_UPDATE_REQUEST",
    "CONFIG_UPDATE_RESPONSE",
    "CONTROL_REQUEST",
    "CONTROL_RESPONSE",
    "CREATE_USER_MESSAGE_REQUEST",
    "CREATE_USER_MESSAGE_RESPONSE",
    "DELETE_USER_MESSAGE_REQUEST",
    "DELETE_USER_MESSAGE_RESPONSE",
    "DISCOVER_REQUEST",
    "DISCOVER_RESPONSE",
    "ERROR_RESPONSE",
    "EXCLUSION_EVENT",
    "HMIP_SYSTEM_EVENT",
    "HMIP_SYSTEM_REQUEST",
    "HMIP_SYSTEM_RESPONSE",
    "INCLUSION_EVENT",
    "LIST_USER_MESSAGES_REQUEST",
    "LIST_USER_MESSAGES_RESPONSE",
    "PLUGIN_STATE_REQUEST",
    "PLUGIN_STATE_RESPONSE",
    "STATUS_EVENT",
    "STATUS_REQUEST",
    "STATUS_RESPONSE",
    "SYSTEM_INFO_REQUEST",
    "SYSTEM_INFO_RESPONSE",
    "USER_MESSAGE_ACK_EVENT",
]
"""Enumerated type of messages sent by Home Control Unit or plugin. The type is included in every message and defines the structure of the message body."""

# 6.6.9. PluginReadinessStatus
PluginReadinessStatus: TypeAlias = Literal["CONFIG_REQUIRED", "ERROR", "READY"]
"""Enumerated type of the plugin state. Included in a PluginStateResponse sent by the plugin to the Home Control Unit."""

# 6.6.10. PresenceType
PresenceType: TypeAlias = Literal["AWAY", "DEFAULT", "HOME", "NORMAL", "VACATION"]
"""Enumerated type of presence modes. Used by plugin devices supporting the PresenceMode feature."""

# 6.6.11. PropertyType
PropertyType: TypeAlias = Literal[
    "BOOLEAN",
    "ENUM",
    "INTEGER",
    "NUMBER",
    "PASSWORD",
    "QRCODE",
    "READONLY",
    "STRING",
    "TYPEAHEAD",
    "WEBLINK",
]
"""Enumerated data type of a plugin configuration property defined in a property template."""

# 6.6.12. ShadingDirection
ShadingDirection: TypeAlias = Literal["DARKER", "LIGHTER"]
"""Enumerated type of shading directions. Used by plugin devices supporting the ShutterDirection feature."""
