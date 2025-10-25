from typing import Any, Literal, TypeAlias, TypedDict

from .hmip_system import EventTransaction
from .schemas import ErrorSchema
from .types import BehaviorType, MessageCategory, AckType


# 6.2. Envelopes
# 6.2.1. PluginMessage
class _BasePluginMessage(TypedDict):
    """Envelope for messages sent by Home Control Unit or plugins."""

    id: str
    pluginId: str


# 6.3. Messages from plugin to Home Control Unit


# 6.3.1 ConfigTemplateResponse
class ConfigTemplateResponseBody(TypedDict):
    properties: dict[str, Any]  # pyright: ignore[reportExplicitAny]


class ConfigTemplateResponse(_BasePluginMessage):
    type: Literal["CONFIG_TEMPLATE_RESPONSE"]
    body: ConfigTemplateResponseBody


# 6.3.2 ConfigUpdateResponse
class ConfigUpdateResponseBody(TypedDict):
    status: str


class ConfigUpdateResponse(_BasePluginMessage):
    type: Literal["CONFIG_UPDATE_RESPONSE"]
    body: ConfigUpdateResponseBody


# 6.3.3 ControlResponse
class ControlResponseBody(TypedDict, total=False):
    deviceId: str
    success: bool
    error: ErrorSchema


class ControlResponse(_BasePluginMessage):
    type: Literal["CONTROL_RESPONSE"]
    body: ControlResponseBody


# 6.3.4 CreateUserMessageRequest
class CreateUserMessageRequestBody(TypedDict):
    behaviorType: BehaviorType
    message: dict[str, str]
    messageCategory: MessageCategory
    timestamp: int
    title: dict[str, str]
    userMessageId: str


class CreateUserMessageRequest(_BasePluginMessage):
    type: Literal["CREATE_USER_MESSAGE_REQUEST"]
    body: CreateUserMessageRequestBody


# 6.3.5 DeleteUserMessageRequest
class DeleteUserMessageRequestBody(TypedDict):
    userMessageId: str


class DeleteUserMessageRequest(_BasePluginMessage):
    type: Literal["DELETE_USER_MESSAGE_REQUEST"]
    body: DeleteUserMessageRequestBody


# 6.3.6 DiscoverResponse
class DiscoverResponseBody(TypedDict, total=False):
    devices: list[dict[str, Any]]  # pyright: ignore[reportExplicitAny]
    success: bool
    error: ErrorSchema


class DiscoverResponse(_BasePluginMessage):
    type: Literal["DISCOVER_RESPONSE"]
    body: DiscoverResponseBody


# 6.3.7 HmipSystemRequest
class HmipSystemRequestBody(TypedDict):
    path: str
    body: dict[str, Any]  # pyright: ignore[reportExplicitAny]


class HmipSystemRequest(_BasePluginMessage):
    type: Literal["HMIP_SYSTEM_REQUEST"]
    body: HmipSystemRequestBody


# 6.3.8 ListUserMessagesRequest
class ListUserMessagesRequestBody(TypedDict):
    # Intentionally empty body
    pass


class ListUserMessagesRequest(_BasePluginMessage):
    type: Literal["LIST_USER_MESSAGES_REQUEST"]
    body: ListUserMessagesRequestBody


# 6.3.9 PluginStateResponse
class PluginStateResponseBody(TypedDict):
    pluginReadinessStatus: str
    friendlyName: dict[str, str]


class PluginStateResponse(_BasePluginMessage):
    type: Literal["PLUGIN_STATE_RESPONSE"]
    body: PluginStateResponseBody


# 6.3.10 StatusEvent
class StatusEventBody(TypedDict):
    deviceId: str
    features: list[dict[str, Any]]  # pyright: ignore[reportExplicitAny]


class StatusEvent(_BasePluginMessage):
    type: Literal["STATUS_EVENT"]
    body: StatusEventBody


# 6.3.11 StatusResponse
class StatusResponseBody(TypedDict, total=False):
    devices: list[dict[str, Any]]  # pyright: ignore[reportExplicitAny]
    success: bool
    error: ErrorSchema


class StatusResponse(_BasePluginMessage):
    type: Literal["STATUS_RESPONSE"]
    body: StatusResponseBody


# 6.3.12 SystemInfoRequest
class SystemInfoRequestBody(TypedDict):
    # Intentionally empty body
    pass


class SystemInfoRequest(_BasePluginMessage):
    type: Literal["SYSTEM_INFO_REQUEST"]
    body: SystemInfoRequestBody


# 6.4. Messages from Home Control Unit to plugin


# 6.4.1 ConfigTemplateRequest
class ConfigTemplateRequestBody(TypedDict):
    languageCode: str | None


class ConfigTemplateRequest(_BasePluginMessage):
    type: Literal["CONFIG_TEMPLATE_REQUEST"]
    body: ConfigTemplateRequestBody


# 6.4.2 ConfigUpdateRequest
class ConfigUpdateRequestBody(TypedDict):
    # Intentionally empty body
    languageCode: str | None
    properties: dict[str, Any] | None  # pyright: ignore[reportExplicitAny]


class ConfigUpdateRequest(_BasePluginMessage):
    type: Literal["CONFIG_UPDATE_REQUEST"]
    body: ConfigUpdateRequestBody


# 6.4.3 ControlRequest
class ControlRequestBody(TypedDict):
    deviceId: str
    features: list[dict[str, Any]]  # pyright: ignore[reportExplicitAny]^^


class ControlRequest(_BasePluginMessage):
    type: Literal["CONTROL_REQUEST"]
    body: ControlRequestBody


# 6.4.4 CreateUserMessageResponse
class CreateUserMessageResponseBody(TypedDict):
    success: bool
    userMessageId: str
    error: ErrorSchema | None


class CreateUserMessageResponse(_BasePluginMessage):
    type: Literal["CREATE_USER_MESSAGE_RESPONSE"]
    body: CreateUserMessageResponseBody


# 6.4.5 DeleteUserMessageResponse
class DeleteUserMessageResponseBody(TypedDict):
    success: bool
    userMessageId: str
    error: ErrorSchema | None


class DeleteUserMessageResponse(_BasePluginMessage):
    type: Literal["DELETE_USER_MESSAGE_RESPONSE"]
    body: DeleteUserMessageResponseBody


# 6.4.6 DiscoverRequest
class DiscoverRequest(_BasePluginMessage):
    type: Literal["DISCOVER_REQUEST"]
    body: None


# 6.4.7 ErrorResponse
class ErrorResponseBody(TypedDict):
    error: ErrorSchema
    originalMessage: str


class ErrorResponse(_BasePluginMessage):
    type: Literal["ERROR_RESPONSE"]
    body: ErrorResponseBody


# 6.4.8 ExclusionEvent
class ExclusionEventBody(TypedDict):
    deviceIds: list[str]


class ExclusionEvent(_BasePluginMessage):
    type: Literal["EXCLUSION_EVENT"]
    body: ExclusionEventBody


# 6.4.9 HmipSystemEvent
class HmipSystemEventBody(TypedDict):
    eventTransaction: EventTransaction


class HmipSystemEvent(_BasePluginMessage):
    type: Literal["HMIP_SYSTEM_EVENT"]
    body: HmipSystemEventBody


# 6.4.10 HmipSystemResponse
class HmipSystemResponseBody(TypedDict, total=False):
    code: int
    body: dict[str, Any] | None  # pyright: ignore[reportExplicitAny]


class HmipSystemResponse(_BasePluginMessage):
    type: Literal["HMIP_SYSTEM_RESPONSE"]
    body: HmipSystemResponseBody


# 6.4.11 InclusionEvent
class InclusionEventBody(TypedDict):
    deviceIds: list[str]


class InclusionEvent(_BasePluginMessage):
    type: Literal["INCLUSION_EVENT"]
    body: InclusionEventBody


# 6.4.12 ListUserMessagesResponse
class ListUserMessagesResponseBody(TypedDict):
    userMessageMap: str


class ListUserMessagesResponse(_BasePluginMessage):
    type: Literal["LIST_USER_MESSAGES_RESPONSE"]
    body: ListUserMessagesResponseBody


# 6.4.13 PluginStateRequest
class PluginStateRequest(_BasePluginMessage):
    type: Literal["PLUGIN_STATE_REQUEST"]
    body: None


# 6.4.14 StatusRequest
class StatusRequestBody(TypedDict):
    deviceIds: list[str]


class StatusRequest(_BasePluginMessage):
    type: Literal["STATUS_REQUEST"]
    body: StatusRequestBody


# 6.4.15 SystemInfoResponse
class SystemInfoResponseBody(TypedDict):
    ipAddress: str
    isOnlineMode: bool
    success: bool


class SystemInfoResponse(_BasePluginMessage):
    type: Literal["SYSTEM_INFO_RESPONSE"]
    body: SystemInfoResponseBody


# 6.4.16 UserMessageAcknowledgementEvent
class UserMessageAcknowledgementEventBody(TypedDict):
    ackType: AckType
    userMessageId: str


class UserMessageAcknowledgementEvent(_BasePluginMessage):
    type: Literal["USER_MESSAGE_ACK_EVENT"]
    body: UserMessageAcknowledgementEventBody


# Union of HCU -> plugin messages
IngoingPluginMessage: TypeAlias = (
    ConfigTemplateRequest
    | ConfigUpdateRequest
    | ControlRequest
    | CreateUserMessageResponse
    | DeleteUserMessageResponse
    | DiscoverRequest
    | ErrorResponse
    | ExclusionEvent
    | HmipSystemEvent
    | HmipSystemResponse
    | InclusionEvent
    | ListUserMessagesResponse
    | PluginStateRequest
    | StatusRequest
    | SystemInfoResponse
    | UserMessageAcknowledgementEvent
)


# Union of plugin -> HCU messages
OutgoingPluginMessage: TypeAlias = (
    ConfigTemplateResponse
    | ConfigUpdateResponse
    | ControlResponse
    | CreateUserMessageRequest
    | DeleteUserMessageRequest
    | DiscoverResponse
    | HmipSystemRequest
    | ListUserMessagesRequest
    | PluginStateResponse
    | StatusEvent
    | StatusResponse
    | SystemInfoRequest
)

PluginMessage: TypeAlias = IngoingPluginMessage | OutgoingPluginMessage
