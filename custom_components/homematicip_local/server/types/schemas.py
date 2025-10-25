from typing import Any, TypedDict
from .types import PropertyType, DeviceType

# 6.5. Schemas


class DeviceSchema(TypedDict):
    """Model for a plugin device to be included in a Homematic IP system."""

    deviceId: str
    deviceType: DeviceType
    features: list[Any]  # pyright: ignore[reportExplicitAny]
    firmwareVersion: str | None
    friendlyName: str | None
    modelType: str | None


class ErrorSchema(TypedDict):
    """Schema of an error object that may be included in response messages sent by the plugin or Home Control Unit when an error occurs while processing a message."""

    code: str
    message: str | None


# 6.5.3. GroupTemplate
class GroupTemplate(TypedDict):
    """Template for a group in which properties are presented together."""

    friendlyName: str
    description: str | None
    order: int | None


# 6.5.4. PropertyTemplate
class PropertyTemplate(TypedDict):
    """Template for plugin configuration properties and associated constraints."""

    dataType: PropertyType
    friendlyName: str
    currentValue: str | None
    defaultValue: str | None
    description: str | None
    groupId: str | None
    maximum: int | None
    maximumLength: int | None
    minimum: int | None
    minimumLength: int | None
    order: int | None
    pattern: str | None
    required: bool
    values: list[str] | None
