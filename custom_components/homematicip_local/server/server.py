from collections.abc import Mapping
import json
import logging
import ssl
import threading
import time
from typing import (
    Any,
    Callable,
    Literal,
    TypeAlias,
    TypedDict,
    cast,
    overload,
)
import uuid
import warnings

import requests
from urllib3.exceptions import InsecureRequestWarning
from websocket import WebSocketApp

from .type_checker import type_checker, validate_annotated
from .types.hmip_system import DeviceChannelEvent, Event, SystemState
from .types.hmip_system_requests import (
    DeviceControlRequestBodies,
    GroupHeatingRequestBodies,
    GroupLinkedControlRequestBodies,
    GroupProfileRequestBodies,
    GroupSwitchingRequestBodies,
    HmIPDeviceControlRequestPaths,
    HmIPGroupHeatingRequestPaths,
    HmIPGroupLinkedControlRequestPaths,
    HmIPGroupProfileRequestPaths,
    HmIPGroupSwitchingRequestPaths,
    HmIPHomeHeatingRequestPaths,
    HmIPHomeRequestPaths,
    HmIPHomeSecurityRequestPaths,
    HmIPRoleRequestPaths,
    HmIPSystemGetStateForClientResponseBody,
    HmIPSystemGetStateResponseBody,
    HmIPSystemGetSystemStateResponseBody,
    HmIPSystemRequestPaths,
    HmIPSystemSetExtendedZonesActivationResponseBody,
    HmIpSystemResponseBody,
    HomeHeatingRequestBodies,
    HomeRequestBodies,
    HomeSecurityRequestBodies,
    RoleRequestBodies,
)
from .types.messages import (
    ConfigTemplateRequestBody,
    ConfigUpdateRequestBody,
    HmipSystemEventBody,
    PluginMessage,
)

plugin_id = "com.homeassistant.custom"


class PendingEntry(TypedDict):
    """Type for entries stored in HCUController._pending.

    Keys:
    - expected_type: the response type expected for a given request id
    - event: a threading.Event used to signal response arrival
    - response: the response payload (or None until set)
    """

    expected_type: str
    event: threading.Event
    response: dict[str, Any] | None  # pyright: ignore[reportExplicitAny]


PendingMap: TypeAlias = dict[str, PendingEntry]


def make_request(ip: str, method: str, path: str, data: dict[str, Any]):  # pyright: ignore[reportExplicitAny]
    headers = {"VERSION": "12"}
    # Suppress only this self-signed HTTPS request warning
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", InsecureRequestWarning)
        return requests.request(
            method,
            f"https://{ip}:6969/{path}",
            json=data,
            headers=headers,
            verify=False,
        )


def confirm_auth_token(ip: str, auth_token: str, activation_key: str) -> str | None:
    data = {
        "authToken": auth_token,
        "activationKey": activation_key,
    }
    response = make_request(ip, "POST", "hmip/auth/confirmConnectApiAuthToken", data)
    if response.status_code == 200:
        return str(response.json()["clientId"])  # pyright: ignore[reportAny]


def init_hcu_plugin(ip: str, activation_key: str):
    if len(activation_key) != 6:
        raise ValueError("Invalid activation key length")
    data = {
        "pluginId": plugin_id,
        "activationKey": activation_key,
        "friendlyName": {
            "de": "Home Assistant Custom Plugin",
            "en": "Home Assistant Custom Plugin",
        },
    }
    response = make_request(ip, "POST", "hmip/auth/requestConnectApiAuthToken", data)

    if response.status_code == 200:
        auth_token: str = response.json()["authToken"]  # pyright: ignore[reportAny]
        client_id = confirm_auth_token(ip, auth_token, activation_key)
        return {"auth_token": auth_token, "client_id": client_id}


class HCUController:
    """Home Control Unit Controller"""

    plugin_id: str = "com.homeassistant.custom"
    logger: logging.Logger = logging.getLogger("HCUController")
    # Cached system state body returned from getSystemState
    _system_state: SystemState | None
    _state_lock: threading.Lock
    _listeners: list[Callable[[], None]]
    first_connection: bool = True

    def __init__(self, ip: str, activation_key: str, auth_token: str, client_id: str):
        self.logger.setLevel(logging.INFO)
        self.ip: str = ip
        self.activation_key: str = activation_key
        self.auth_token: str = auth_token
        self.client_id: str = client_id
        # Pending requests: id -> { expected_type: str, event: threading.Event, response: dict|None }
        self._pending_lock: threading.Lock = threading.Lock()
        self._pending: PendingMap = {}
        websocket_headers = {
            "authtoken": auth_token,
            "plugin-id": self.plugin_id,
            "hmip-system-events": "true",
        }
        self.ws: WebSocketApp = WebSocketApp(
            f"wss://{self.ip}:9001", header=websocket_headers
        )

        self.ws.on_message = self._ws_message_handler
        self.ws.on_error = self._ws_error_handler
        self.ws.on_close = self._ws_close_handler
        self.ws.on_open = self._ws_open_handler
        # Runtime state
        self._ws_thread: threading.Thread | None = None
        self._ws_open_event: threading.Event = threading.Event()
        self._system_state = None
        self._state_lock = threading.Lock()
        self._listeners = []
        self._device_event_listeners_lock: threading.Lock = threading.Lock()
        self._device_event_listeners: dict[
            str, list[Callable[[int, DeviceChannelEvent], None]]
        ] = {}

    def add_state_listener(self, callback: Callable[[], None]) -> Callable[[], None]:
        """Register a listener invoked when cached system state changes.

        Returns a remover callable.
        """
        self._listeners.append(callback)

        def _remove() -> None:
            try:
                self._listeners.remove(callback)
            except ValueError:
                pass

        return _remove

    def _notify_state_listeners(self) -> None:
        for cb in list(self._listeners):
            try:
                cb()
            except Exception:
                self.logger.exception("State listener failed")

    def start(self) -> None:
        """Start websocket processing in background thread."""
        if self._ws_thread and self._ws_thread.is_alive():
            return

        def _run() -> None:
            backoff: float = 1.0
            max_backoff: float = 30.0
            while True:
                _ok: bool = self.ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})  # pyright: ignore[reportUnknownMemberType]
                if _ok is True:
                    delay = min(backoff, max_backoff)
                    self.logger.warning(
                        "WebSocket will attempt reconnect in %.1fs", delay
                    )
                    time.sleep(delay)
                    backoff = min(backoff * 2.0, max_backoff)
                    continue
                break

        self._ws_thread = threading.Thread(target=_run, name="hcu-ws", daemon=True)
        self._ws_thread.start()

    def stop(self) -> None:
        """Stop websocket processing."""
        try:
            self.ws.close()  # pyright: ignore[reportUnknownMemberType]
        except Exception:
            pass

    def _send_plugin_message(
        self,
        msg_id: str,
        msg_type: str,
        body: dict[str, Any] | None = None,  # pyright: ignore[reportExplicitAny]
    ) -> None:
        data: dict[str, str | dict[str, Any]] = {  # pyright: ignore[reportExplicitAny]
            "pluginId": self.plugin_id,
            "id": msg_id,
            "type": msg_type,
        }
        if body:
            data["body"] = body
        self.ws.send(json.dumps(data))

    def _ws_error_handler(self, ws: WebSocketApp, err: str) -> None:  # pyright: ignore[reportUnusedParameter]
        self.logger.error("WebSocket error: %s", err)

    def _ws_close_handler(self, ws: WebSocketApp, code: str, msg: str) -> None:  # pyright: ignore[reportUnusedParameter]
        self.logger.info("WebSocket closed with code: %d, message: %s", code, msg)

    def _send_plugin_state_response(self, msg_id: str | None = None) -> None:
        if msg_id is None:
            msg_id = str(uuid.uuid4())
        body = {
            "pluginReadinessStatus": "READY",
            "friendlyName": {
                "de": "Home Assistant Custom Plugin",
                "en": "Home Assistant Custom Plugin",
            },
        }
        self._send_plugin_message(msg_id, "PLUGIN_STATE_RESPONSE", body)

    def _handle_plugin_state_request(self, msg_id: str, body: None) -> None:  # pyright: ignore[reportUnusedParameter]
        self._send_plugin_state_response(msg_id)

    def _send_discover_response(self, msg_id: str):
        self.logger.info("Sending discover response")
        body: dict[str, Any] = {  # pyright: ignore[reportExplicitAny]
            "devices": [],
            "success": True,
        }
        self._send_plugin_message(msg_id, "DISCOVER_RESPONSE", body)

    def _handle_discover_request(self, msg_id: str, body: None) -> None:  # pyright: ignore[reportUnusedParameter]
        self._send_discover_response(msg_id)

    def _send_request_message(
        self,
        msg_type: str,
        body: dict[str, Any],  # pyright: ignore[reportExplicitAny]
    ) -> dict[str, Any] | None:  # pyright: ignore[reportExplicitAny]
        msg_id = str(uuid.uuid4())
        expected_type = self._to_response_type(msg_type)
        evt = threading.Event()
        with self._pending_lock:
            self._pending[msg_id] = {
                "expected_type": expected_type,
                "event": evt,
                "response": None,
            }

        self.logger.info(
            "Sending request %s with id %s expecting %s",
            msg_type,
            msg_id,
            expected_type,
        )
        self._send_plugin_message(msg_id, msg_type, body)

        # Wait for matching response
        if not evt.wait(timeout=10):
            with self._pending_lock:
                _ = self._pending.pop(msg_id, None)
            raise TimeoutError(
                f"Timed out waiting for response to {msg_type} with id {msg_id}"
            )

        with self._pending_lock:
            entry = self._pending.pop(msg_id, None)
        if entry and "response" in entry:
            return entry["response"]["body"]  # pyright: ignore[reportUnknownVariableType, reportOptionalSubscript]
        return None

    def _handle_message_response(self, message: PluginMessage) -> None:
        msg_id = message.get("id")
        msg_type = message.get("type")
        plugin_id = message.get("pluginId")
        if not msg_id or not msg_type or not plugin_id:
            return
        if plugin_id != self.plugin_id:
            return
        with self._pending_lock:
            entry = self._pending.get(msg_id)
            if entry and message["body"]:
                expected_type = entry["expected_type"]
                body = message["body"]
                response = {"success": True, "body": body}
                if "error" in body or expected_type == "ERROR_RESPONSE":
                    response["success"] = False
                entry["response"] = response
                entry["event"].set()
                self.logger.debug("Matched response %s for id %s", msg_type, msg_id)
            else:
                # Not a pending request or type mismatch; ignore
                self.logger.error(
                    "Unmatched response: id=%s type=%s (pending=%s)",
                    msg_id,
                    msg_type,
                    bool(entry),
                )

    @staticmethod
    def _to_response_type(request_type: str) -> str:
        if request_type.endswith("_REQUEST"):
            return request_type[:-8] + "_RESPONSE"
        else:
            raise ValueError(f"Unknown request type: {request_type}")

    def _send_config_template_response(self, msg_id: str) -> None:
        self.logger.info("Sending config template response")
        body: dict[str, Any] = {"properties": {}}  # pyright: ignore[reportExplicitAny]
        self._send_plugin_message(msg_id, "CONFIG_TEMPLATE_RESPONSE", body)

    def _handle_config_template_request(
        self,
        msg_id: str,
        body: ConfigTemplateRequestBody,  # pyright: ignore[reportUnusedParameter]
    ) -> None:
        self._send_config_template_response(msg_id)

    def _send_config_update_response(self, msg_id: str) -> None:
        self.logger.info("Sending config template response")
        body = {"status": "APPLIED"}
        self._send_plugin_message(msg_id, "CONFIG_UPDATE_RESPONSE", body)

    def _handle_config_update_request(
        self,
        msg_id: str,
        body: ConfigUpdateRequestBody,  # pyright: ignore[reportUnusedParameter]
    ) -> None:
        self._send_config_update_response(msg_id)

    def _plugin_message_handler(self, ws: WebSocketApp, message: PluginMessage) -> None:  # pyright: ignore[reportUnusedParameter]
        message_body = message["body"]
        message_str = json.dumps(message)
        if len(message_str) > 150:
            message_str = ""
            if (
                isinstance(message_body, dict)
                and "code" in message_body
                and isinstance(message_body.get("body"), dict)
            ):
                inner = message_body.get("body")
                if inner:
                    message_str += f"keys: {list(inner.keys())}"
                else:
                    message_str += f"keys: {list(message_body.keys())}"
                message_str += f" code: {message_body.get('code')}"
            elif isinstance(message_body, dict):
                message_str += f"keys: {list(message_body.keys())}"
            else:
                message_str += "body: None"
        else:
            message_str = message_body
        plugin_str = ""
        if message["pluginId"] != self.plugin_id:
            plugin_str = f', pluginId: "{message["pluginId"]}"'
        self.logger.info(
            'Plugin message received: id: "%s", type: "%s"%s, body: "%s"',
            message["id"],
            message["type"],
            plugin_str,
            message_str,
        )
        if message["type"] == "PLUGIN_STATE_REQUEST":
            self._handle_plugin_state_request(message["id"], message["body"])
        elif message["type"] == "DISCOVER_REQUEST":
            self._handle_discover_request(message["id"], message["body"])
        elif message["type"] == "CONFIG_TEMPLATE_REQUEST":
            self._handle_config_template_request(message["id"], message["body"])
        elif message["type"] == "CONFIG_UPDATE_REQUEST":
            self._handle_config_update_request(message["id"], message["body"])
        elif message["type"].lower().endswith("response"):
            self._handle_message_response(message)
        elif message["type"].lower().endswith("event"):
            self._handle_system_event(message)
        else:
            self.logger.warning(
                "Unknown plugin message type: %s body=%s", message["type"], message
            )

    # Overloads mapping each path to its corresponding request body type
    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPHomeRequestPaths.getSystemState],
        body: HomeRequestBodies.Empty,
    ) -> HmIPSystemGetSystemStateResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPHomeRequestPaths.getState],
        body: HomeRequestBodies.Empty,
    ) -> HmIPSystemGetStateResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPHomeRequestPaths.getStateForClient],
        body: HomeRequestBodies.Empty,
    ) -> HmIPSystemGetStateForClientResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPHomeRequestPaths.checkAuthToken],
        body: HomeRequestBodies.Empty,
    ) -> HmIpSystemResponseBody: ...

    # Group Profile
    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupProfileRequestPaths.setProfileMode],
        body: GroupProfileRequestBodies.SetProfileModeRequestBody,
    ) -> HmIpSystemResponseBody: ...

    # Role
    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPRoleRequestPaths.enableSimpleRule],
        body: RoleRequestBodies.EnableSimpleRule,
    ) -> HmIpSystemResponseBody: ...

    # Home Heating
    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPHomeHeatingRequestPaths.activateAbsencePermanent],
        body: HomeRequestBodies.Empty,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPHomeHeatingRequestPaths.activateAbsenceWithDuration],
        body: HomeHeatingRequestBodies.ActivateAbsenceWithDuration,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPHomeHeatingRequestPaths.activateAbsenceWithFuturePeriod],
        body: HomeHeatingRequestBodies.ActivateAbsenceWithFuturePeriod,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPHomeHeatingRequestPaths.activateAbsenceWithPeriod],
        body: HomeHeatingRequestBodies.ActivateAbsenceWithPeriod,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPHomeHeatingRequestPaths.activateFutureVacation],
        body: HomeHeatingRequestBodies.ActivateFutureVacation,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPHomeHeatingRequestPaths.activateVacation],
        body: HomeHeatingRequestBodies.ActivateVacation,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPHomeHeatingRequestPaths.deactivateAbsence],
        body: Mapping[str, object],
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPHomeHeatingRequestPaths.deactivateVacation],
        body: Mapping[str, object],
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPHomeHeatingRequestPaths.setCooling],
        body: HomeHeatingRequestBodies.SetCooling,
    ) -> HmIpSystemResponseBody: ...

    # Group Heating
    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupHeatingRequestPaths.activatePartyMode],
        body: GroupHeatingRequestBodies.HmIPActivatePartyMode,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupHeatingRequestPaths.setActiveProfile],
        body: GroupHeatingRequestBodies.HmIPSetActiveProfile,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupHeatingRequestPaths.setBoost],
        body: GroupHeatingRequestBodies.HmIPSetBoost,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupHeatingRequestPaths.setControlMode],
        body: GroupHeatingRequestBodies.HmIPSetControlMode,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupHeatingRequestPaths.setHotWaterOnTime],
        body: GroupHeatingRequestBodies.HmIPSetHotWaterOnTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupHeatingRequestPaths.setHotWaterProfileMode],
        body: GroupHeatingRequestBodies.HmIPSetHotWaterProfileMode,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupHeatingRequestPaths.setHotWaterState],
        body: GroupHeatingRequestBodies.HmIPSetHotWaterState,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupHeatingRequestPaths.setSetPointTemperature],
        body: GroupHeatingRequestBodies.HmIPSetPointTemperature,
    ) -> HmIpSystemResponseBody: ...

    # Home Security
    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPHomeSecurityRequestPaths.setExtendedZonesActivation],
        body: HomeSecurityRequestBodies.SetExtendedZonesActivation,
    ) -> HmIPSystemSetExtendedZonesActivationResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPHomeSecurityRequestPaths.setZonesActivation],
        body: HomeSecurityRequestBodies.SetZonesActivation,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPHomeSecurityRequestPaths.acknowledgeSafetyAlarm],
        body: Mapping[str, object],
    ) -> HmIpSystemResponseBody: ...

    # Group Linked Control
    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[
            HmIPGroupLinkedControlRequestPaths.setOpticalSignalBehaviour
        ],
        body: GroupLinkedControlRequestBodies.HmIPSetOpticalSignalBehaviour,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupLinkedControlRequestPaths.setSoundFileVolumeLevel],
        body: GroupLinkedControlRequestBodies.SetSoundFileVolumeLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupLinkedControlRequestPaths.setVentilationLevel],
        body: GroupLinkedControlRequestBodies.HmIPSetVentilationLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[
            HmIPGroupLinkedControlRequestPaths.setVentilationLevelWithTime
        ],
        body: GroupLinkedControlRequestBodies.HmIPSetVentilationLevelWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupLinkedControlRequestPaths.setVentilationState],
        body: GroupLinkedControlRequestBodies.HmIPSetVentilationState,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[
            HmIPGroupLinkedControlRequestPaths.setVentilationStateWithTime
        ],
        body: GroupLinkedControlRequestBodies.HmIPSetVentilationStateWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupLinkedControlRequestPaths.setWateringSwitchState],
        body: GroupLinkedControlRequestBodies.HmIPSetWateringSwitchState,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[
            HmIPGroupLinkedControlRequestPaths.setWateringSwitchStateWithTime
        ],
        body: GroupLinkedControlRequestBodies.HmIPSetWateringSwitchStateWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupLinkedControlRequestPaths.startNotification],
        body: GroupLinkedControlRequestBodies.GroupId,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupLinkedControlRequestPaths.stopNotification],
        body: GroupLinkedControlRequestBodies.GroupId,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupLinkedControlRequestPaths.toggleVentilationState],
        body: GroupLinkedControlRequestBodies.GroupId,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupLinkedControlRequestPaths.toggleWateringState],
        body: GroupLinkedControlRequestBodies.GroupId,
    ) -> HmIpSystemResponseBody: ...

    # Group Switching
    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupSwitchingRequestPaths.setColorTemperatureDimLevel],
        body: GroupSwitchingRequestBodies.SetColorTemperatureDimLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[
            HmIPGroupSwitchingRequestPaths.setColorTemperatureDimLevelWithTime
        ],
        body: GroupSwitchingRequestBodies.SetColorTemperatureDimLevelWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupSwitchingRequestPaths.setDimLevel],
        body: GroupSwitchingRequestBodies.SetDimLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupSwitchingRequestPaths.setDimLevelWithTime],
        body: GroupSwitchingRequestBodies.SetDimLevelWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupSwitchingRequestPaths.setFavoriteShadingPosition],
        body: GroupSwitchingRequestBodies.HmIPGroupsSwitching,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupSwitchingRequestPaths.setHueSaturationDimLevel],
        body: GroupSwitchingRequestBodies.SetHueSaturationDimLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[
            HmIPGroupSwitchingRequestPaths.setHueSaturationDimLevelWithTime
        ],
        body: GroupSwitchingRequestBodies.SetHueSaturationDimLevelWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupSwitchingRequestPaths.setPrimaryShadingLevel],
        body: GroupSwitchingRequestBodies.SetPrimaryShadingLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupSwitchingRequestPaths.setSecondaryShadingLevel],
        body: GroupSwitchingRequestBodies.SetSecondaryShadingLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupSwitchingRequestPaths.setState],
        body: GroupSwitchingRequestBodies.SetSwitchState,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupSwitchingRequestPaths.setSwitchStateWithTime],
        body: GroupSwitchingRequestBodies.SetSwitchStateWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupSwitchingRequestPaths.startLightScene],
        body: GroupSwitchingRequestBodies.StartLightScene,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupSwitchingRequestPaths.stop],
        body: GroupSwitchingRequestBodies.HmIPGroupsSwitching,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupSwitchingRequestPaths.toggleShadingState],
        body: GroupSwitchingRequestBodies.HmIPGroupsSwitching,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupSwitchingRequestPaths.toggleSwitchState],
        body: GroupSwitchingRequestBodies.HmIPGroupsSwitching,
    ) -> HmIpSystemResponseBody: ...

    # Device Control
    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setDimLevel],
        body: DeviceControlRequestBodies.SetDimLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setDimLevelWithTime],
        body: DeviceControlRequestBodies.SetDimLevelWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setColorTemperatureDimLevel],
        body: DeviceControlRequestBodies.SetColorTemperatureDimLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[
            HmIPDeviceControlRequestPaths.setColorTemperatureDimLevelWithTime
        ],
        body: DeviceControlRequestBodies.SetColorTemperatureDimLevelWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setHueSaturationDimLevel],
        body: DeviceControlRequestBodies.SetHueSaturationDimLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[
            HmIPDeviceControlRequestPaths.setHueSaturationDimLevelWithTime
        ],
        body: DeviceControlRequestBodies.SetHueSaturationDimLevelWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setSwitchState],
        body: DeviceControlRequestBodies.SetSwitchState,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setSwitchStateForIdentify],
        body: DeviceControlRequestBodies.SetSwitchState,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setSwitchStateWithTime],
        body: DeviceControlRequestBodies.SetSwitchStateWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setDoorLockActive],
        body: DeviceControlRequestBodies.SetDoorLockActive,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[
            HmIPDeviceControlRequestPaths.setDoorLockActiveWithAuthorization
        ],
        body: DeviceControlRequestBodies.SetDoorLockActiveWithAuthorization,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setLockState],
        body: DeviceControlRequestBodies.SetLockState,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setMotionDetectionActive],
        body: DeviceControlRequestBodies.SetMotionDetectionActive,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setOpticalSignal],
        body: DeviceControlRequestBodies.SetOpticalSignalBase,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setOpticalSignalWithTime],
        body: DeviceControlRequestBodies.SetOpticalSignalWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setPrimaryShadingLevel],
        body: DeviceControlRequestBodies.SetPrimaryShadingLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setSecondaryShadingLevel],
        body: DeviceControlRequestBodies.SetSecondaryShadingLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setShutterLevel],
        body: DeviceControlRequestBodies.SetShutterLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setSimpleRGBColorDimLevel],
        body: DeviceControlRequestBodies.SetSimpleRGBColorDimLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[
            HmIPDeviceControlRequestPaths.setSimpleRGBColorDimLevelWithTime
        ],
        body: DeviceControlRequestBodies.SetSimpleRGBColorDimLevelWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setSlatsLevel],
        body: DeviceControlRequestBodies.SetSlatsLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setSoundFileVolumeLevel],
        body: DeviceControlRequestBodies.SetSoundFileVolumeLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[
            HmIPDeviceControlRequestPaths.setSoundFileVolumeLevelWithTime
        ],
        body: DeviceControlRequestBodies.SetSoundFileVolumeLevelWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setVentilationLevel],
        body: DeviceControlRequestBodies.SetVentilationLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setVentilationLevelWithTime],
        body: DeviceControlRequestBodies.SetVentilationLevelWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setVentilationState],
        body: DeviceControlRequestBodies.SetVentilationState,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setVentilationStateWithTime],
        body: DeviceControlRequestBodies.SetVentilationStateWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setWateringSwitchState],
        body: DeviceControlRequestBodies.SetWateringSwitchState,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[
            HmIPDeviceControlRequestPaths.setWateringSwitchStateWithTime
        ],
        body: DeviceControlRequestBodies.SetWateringSwitchStateWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.startLightScene],
        body: DeviceControlRequestBodies.StartLightScene,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.sendDoorCommand],
        body: DeviceControlRequestBodies.SendDoorCommand,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.pullLatch],
        body: DeviceControlRequestBodies.PullLatch,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[
            HmIPDeviceControlRequestPaths.acknowledgeFrostProtectionError
        ],
        body: DeviceControlRequestBodies.HmIPDeviceControl,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.resetBlocking],
        body: DeviceControlRequestBodies.HmIPDeviceControl,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.resetEnergyCounter],
        body: DeviceControlRequestBodies.HmIPDeviceControl,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.resetPassageCounter],
        body: DeviceControlRequestBodies.HmIPDeviceControl,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.resetWaterVolume],
        body: DeviceControlRequestBodies.HmIPDeviceControl,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setFavoriteShadingPosition],
        body: DeviceControlRequestBodies.HmIPDeviceControl,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setIdentify],
        body: DeviceControlRequestBodies.HmIPDeviceControl,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setIdentifyOem],
        body: DeviceControlRequestBodies.HmIPDeviceControl,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.startImpulse],
        body: DeviceControlRequestBodies.HmIPDeviceControl,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.stop],
        body: DeviceControlRequestBodies.HmIPDeviceControl,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.toggleCameraNightVision],
        body: DeviceControlRequestBodies.HmIPDeviceControl,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.toggleGarageDoorState],
        body: DeviceControlRequestBodies.HmIPDeviceControl,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.toggleShadingState],
        body: DeviceControlRequestBodies.HmIPDeviceControl,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.toggleSwitchState],
        body: DeviceControlRequestBodies.HmIPDeviceControl,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.toggleVentilationState],
        body: DeviceControlRequestBodies.HmIPDeviceControl,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.toggleWateringState],
        body: DeviceControlRequestBodies.HmIPDeviceControl,
    ) -> HmIpSystemResponseBody: ...

    @type_checker
    def _send_hmip_system_request(
        self, hmip_path: HmIPSystemRequestPaths, body: object
    ) -> HmIpSystemResponseBody:
        request_body: dict[str, Any] = {"path": hmip_path.value, "body": body}  # pyright: ignore[reportExplicitAny]
        self.logger.info(
            "Sending HMIP system request: path=%s, body=%s",
            hmip_path.value,
            body,
        )
        return cast(  # pyright: ignore[reportAny]
            Any,  # pyright: ignore[reportExplicitAny]
            self._send_request_message("HMIP_SYSTEM_REQUEST", request_body),
        )

    def _handle_system_event(self, message: PluginMessage) -> None:
        if message["type"] == "HMIP_SYSTEM_EVENT":
            self._handle_hmip_system_event(message["body"])
        else:
            self.logger.warning(
                "Unknown system event type: %s message=%s", message["type"], message
            )

    def _handle_hmip_system_event(self, body: HmipSystemEventBody) -> None:
        # 1. Validate top-level body against its annotation
        summary_types = [
            ev["pushEventType"] for ev in body["eventTransaction"]["events"].values()
        ]
        self.logger.info("HMIP system event received (types=%s)", summary_types)
        try:
            issues = validate_annotated(body)
            if issues:
                unexpected = [i for i in issues if "unexpected key" in i]
                log_fn = self.logger.error if unexpected else self.logger.warning
                log_fn(
                    "HMIP system event body type issues (first %d): %s, body=%s",
                    min(10, len(issues)),
                    issues[:10],
                    body,
                )
                self.logger.info(body)
        except Exception:  # pragma: no cover - defensive
            self.logger.exception("validate_annotated failed for system event body")

        # Merge incoming events into cached state and notify listeners
        try:
            with self._state_lock:
                if self._system_state is None:
                    return

                state: SystemState = self._system_state

                def _get_map(
                    key: Literal["groups", "clients", "home", "devices"],
                ) -> dict[str, object]:
                    cur = state[key]
                    return cast(dict[str, object], cur)

                events: dict[str, Event] = body["eventTransaction"]["events"]
                for ev_map in events.values():
                    if ev_map["pushEventType"] == "DEVICE_CHANNEL_EVENT":
                        self.logger.info("HMIP DEVICE_CHANNEL_EVENT: %s", ev_map)
                        ts = body["eventTransaction"]["timestamp"]
                        did = ev_map["deviceId"]
                        if did:
                            callbacks: list[Callable[[int, DeviceChannelEvent], None]]
                            with self._device_event_listeners_lock:
                                callbacks = list(
                                    self._device_event_listeners.get(did, [])
                                )
                            for cb in callbacks:
                                try:
                                    cb(ts, ev_map)
                                except Exception:
                                    self.logger.exception(
                                        "Device event listener failed for %s", did
                                    )
                    elif ev_map["pushEventType"] == "HOME_CHANGED":
                        state["home"] = ev_map["home"]
                    elif (
                        ev_map["pushEventType"] == "DEVICE_ADDED"
                        or ev_map["pushEventType"] == "DEVICE_CHANGED"
                    ):
                        dev = ev_map["device"]
                        did = dev["id"]
                        if did:
                            _get_map("devices")[did] = dev
                    elif ev_map["pushEventType"] == "DEVICE_REMOVED":
                        did_obj = ev_map["id"]
                        with self._state_lock:
                            _ = self._system_state["devices"].pop(did_obj, None)
                    elif (
                        ev_map["pushEventType"] == "GROUP_ADDED"
                        or ev_map["pushEventType"] == "GROUP_CHANGED"
                    ):
                        grp = ev_map["group"]
                        gid = grp["id"]
                        if gid:
                            _get_map("groups")[gid] = grp
                    elif ev_map["pushEventType"] == "GROUP_REMOVED":
                        gid = ev_map["id"]
                        if gid:
                            _ = _get_map("groups").pop(gid, None)
                    elif (
                        ev_map["pushEventType"] == "CLIENT_ADDED"
                        or ev_map["pushEventType"] == "CLIENT_CHANGED"
                    ):
                        client = ev_map["client"]
                        cid = client["id"]
                        if cid:
                            _get_map("clients")[cid] = client
                    elif ev_map["pushEventType"] == "CLIENT_REMOVED":
                        cid = ev_map.get("id")
                        if cid:
                            _ = _get_map("clients").pop(cid, None)
                    else:
                        logging.getLogger(__name__).warning(
                            "HMIP unknown event: %s", ev_map
                        )

        except Exception:
            self.logger.exception("Failed merging HMIP system event into state")
        else:
            self._notify_state_listeners()

    def set_security_zone_active(self, zone_id: str, active: bool) -> None:
        """Set activation state of a security zone."""
        body: HomeSecurityRequestBodies.SetZonesActivation = {
            "zonesActivation": {zone_id: active}
        }
        _ = self._send_hmip_system_request(
            HmIPHomeSecurityRequestPaths.setZonesActivation,
            body,
        )

    def set_heating_control_mode(
        self, group_id: str, mode: Literal["AUTOMATIC", "MANUAL", "ECO"]
    ) -> None:
        body: GroupHeatingRequestBodies.HmIPSetControlMode = {
            "groupId": group_id,
            "controlMode": mode,
        }
        _ = self._send_hmip_system_request(
            HmIPGroupHeatingRequestPaths.setControlMode,
            body,
        )

    def add_device_event_listener(
        self, device_id: str, callback: Callable[[int, DeviceChannelEvent], None]
    ) -> Callable[[], None]:
        """Register a callback for DEVICE_CHANNEL_EVENTs of a given device.

        Returns a remove callback.
        """
        with self._device_event_listeners_lock:
            lst = self._device_event_listeners.get(device_id)
            if lst is None:
                lst = []
                self._device_event_listeners[device_id] = lst
            lst.append(callback)

        def _remove() -> None:
            with self._device_event_listeners_lock:
                lst2 = self._device_event_listeners.get(device_id)
                if lst2 and callback in lst2:
                    try:
                        lst2.remove(callback)
                    except ValueError:
                        pass
                    if not lst2:
                        _ = self._device_event_listeners.pop(device_id, None)

        return _remove

    def _ws_open_handler(self, ws: WebSocketApp) -> None:  # pyright: ignore[reportUnusedParameter]
        self.logger.info("WebSocket connection opened")
        self._ws_open_event.set()
        self._send_plugin_state_response()
        if not self.first_connection:
            self.first_connection = False
            threading.Thread(
                target=self._send_initial_hmip_system_request,
                name="hcu-request-worker",
                args=(),
                daemon=True,
            ).start()

    def _send_initial_hmip_system_request(self) -> None:
        """Send an initial system state fetch after WS open."""
        try:
            response = self._send_hmip_system_request(
                HmIPHomeRequestPaths.getSystemState, {}
            )
            self._system_state = response["body"]
        except Exception as exc:
            self.logger.exception("Initial HMIP request failed: %s", exc)
        else:
            self._notify_state_listeners()

    def wait_until_ready(self, timeout: float = 5.0) -> bool:
        """Block until websocket on_open fired."""
        return self._ws_open_event.wait(timeout)

    def get_system_state(self) -> SystemState:
        """Return cached system state if present; try to fetch if missing."""
        if self._system_state is None:
            resp = self._send_hmip_system_request(
                HmIPHomeRequestPaths.getSystemState, {}
            )
            self._system_state = resp["body"]
        return self._system_state

    def _ws_message_handler(self, ws: WebSocketApp, message: str) -> None:
        json_message = cast(PluginMessage, json.loads(message))
        if json_message["pluginId"] == self.plugin_id:
            self._plugin_message_handler(ws, json_message)
        else:
            self.logger.warning(
                "Unknown plugin message received: %s", json.dumps(json_message)
            )

    # ---- Public convenience API wrappers -------------------------------------------------
    def set_heating_group_setpoint(self, group_id: str, temperature: float) -> None:
        """Set target temperature on a heating group.

        This is a thin wrapper around the GroupHeating setSetPointTemperature request.
        """
        try:
            _ = self._send_hmip_system_request(
                HmIPGroupHeatingRequestPaths.setSetPointTemperature,
                {"groupId": group_id, "setPointTemperature": float(temperature)},
            )
        except Exception:
            self.logger.exception(
                "Failed to send setSetPointTemperature for group %s", group_id
            )

    def set_notification_light(
        self,
        device_id: str,
        channel_index: int,
        *,
        simple_rgb_color_state: str = "WHITE",
        optical_signal_behaviour: str = "ON",
        dim_level: float = 1.0,
    ) -> None:
        """Control Access Point notification light via setOpticalSignal.

        Params:
        - device_id: HCU device id (ACCESS_POINT)
        - channel_index: notification light channel index (usually 1)
        - simple_rgb_color_state: one of BLACK/BLUE/GREEN/TURQUOISE/RED/PURPLE/YELLOW/WHITE
        - optical_signal_behaviour: OFF/ON/BLINKING_MIDDLE/FLASH_MIDDLE/BILLOW_MIDDLE
        - dim_level: 0.0 .. 1.0
        """
        try:
            body: DeviceControlRequestBodies.SetOpticalSignalBase = {
                "deviceId": device_id,
                "channelIndex": int(channel_index),
                "simpleRGBColorState": str(simple_rgb_color_state),
                "opticalSignalBehaviour": str(optical_signal_behaviour),
                "dimLevel": float(dim_level),
            }
            _ = self._send_hmip_system_request(
                HmIPDeviceControlRequestPaths.setOpticalSignal,
                body,
            )
        except Exception:
            self.logger.exception(
                "Failed to control notification light for device %s ch %s",
                device_id,
                channel_index,
            )

    def set_dimmer_level(
        self, device_id: str, channel_index: int, *, dim_level: float
    ) -> None:
        """Set dim level (0.0..1.0) on a DIMMER_CHANNEL.

        Uses the Device Control setDimLevel endpoint. Note: the type schema in
        hmip_device_control annotates dimLevel as int, but HmIP expects a
        fractional level between 0.0 and 1.0. We pass float; the runtime
        validator may warn but the device accepts it.
        """
        try:
            body: DeviceControlRequestBodies.SetDimLevel = {
                "deviceId": device_id,
                "channelIndex": int(channel_index),
                "dimLevel": dim_level,
            }
            _ = self._send_hmip_system_request(
                HmIPDeviceControlRequestPaths.setDimLevel,
                body,
            )
            self.logger.error(
                "Set dim level for device %s ch %s -> %s, %s",
                device_id,
                channel_index,
                dim_level,
                _,
            )
        except Exception:
            self.logger.exception(
                "Failed to set dim level for device %s ch %s -> %s",
                device_id,
                channel_index,
                dim_level,
            )

    def set_switch_state(self, device_id: str, channel_index: int, *, on: bool) -> None:
        """Set switch state on a SWITCH_CHANNEL via setSwitchState."""
        try:
            body: DeviceControlRequestBodies.SetSwitchState = {
                "deviceId": device_id,
                "channelIndex": int(channel_index),
                "on": bool(on),
            }
            _ = self._send_hmip_system_request(
                HmIPDeviceControlRequestPaths.setSwitchState,
                body,
            )
        except Exception:
            self.logger.exception(
                "Failed to set switch state for device %s ch %s -> %s",
                device_id,
                channel_index,
                on,
            )

    def set_hue_saturation_dim_level(
        self,
        device_id: str,
        channel_index: int,
        *,
        hue: int,
        saturation_level: float,
        dim_level: float,
    ) -> None:
        """Set HS + brightness on a UNIVERSAL_LIGHT_CHANNEL using setHueSaturationDimLevel.

        hue: 0..359
        saturation_level: 0.0..1.0
        dim_level: 0.0..1.0
        """
        try:
            body: DeviceControlRequestBodies.SetHueSaturationDimLevel = {
                "deviceId": device_id,
                "channelIndex": int(channel_index),
                "hue": int(max(0, min(359, hue))),
                # schema types mark saturationLevel/dimLevel as int, but device expects float 0..1
                "saturationLevel": max(
                    0.0,
                    min(1.0, saturation_level),
                ),  # type: ignore[arg-type]
                "dimLevel": cast(int, float(max(0.0, min(1.0, dim_level)))),  # type: ignore[arg-type]
            }
            _ = self._send_hmip_system_request(
                HmIPDeviceControlRequestPaths.setHueSaturationDimLevel,
                body,
            )
        except Exception:
            self.logger.exception(
                "Failed to set HS for device %s ch %s (h=%s s=%s dim=%s)",
                device_id,
                channel_index,
                hue,
                saturation_level,
                dim_level,
            )

    def set_color_temperature_dim_level(
        self,
        device_id: str,
        channel_index: int,
        *,
        color_temperature: int,
        dim_level: float,
    ) -> None:
        """Set color temperature (Kelvin) + brightness on a UNIVERSAL_LIGHT_CHANNEL."""
        try:
            body: DeviceControlRequestBodies.SetColorTemperatureDimLevel = {
                "deviceId": device_id,
                "channelIndex": int(channel_index),
                "colorTemperature": int(color_temperature),
                "dimLevel": cast(int, float(max(0.0, min(1.0, dim_level)))),  # type: ignore[arg-type]
            }
            _ = self._send_hmip_system_request(
                HmIPDeviceControlRequestPaths.setColorTemperatureDimLevel,
                body,
            )
        except Exception:
            self.logger.exception(
                "Failed to set CT for device %s ch %s (K=%s dim=%s)",
                device_id,
                channel_index,
                color_temperature,
                dim_level,
            )
