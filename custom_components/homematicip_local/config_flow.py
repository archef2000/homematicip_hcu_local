from __future__ import annotations

import re
from typing import override

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.config_entries import ConfigFlowResult

from .const import DOMAIN
from .server.server import confirm_auth_token, init_hcu_plugin


class HomematicIPLocalConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for HomematicIP Local HCU."""

    VERSION: int = 1

    def __init__(self) -> None:
        self._host: str | None = None
        self._activation_key: str | None = None
        self._existing: bool = False

    @override
    async def async_step_user(
        self, user_input: dict[str, object] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            host = str(user_input.get("host", "")).strip()
            activation_key = str(user_input.get("activation_key", "")).strip()
            existing = bool(user_input.get("existing_credentials", False))

            if not re.fullmatch(r"[A-Za-z0-9]{6}", activation_key):
                errors["activation_key"] = "invalid_activation_key"
            else:
                _ = await self.async_set_unique_id(host)
                self._abort_if_unique_id_configured()

                self._host = host
                self._activation_key = activation_key
                self._existing = existing

                if existing:
                    return await self.async_step_credentials()

                try:
                    result = await self.hass.async_add_executor_job(
                        init_hcu_plugin, host, activation_key
                    )
                except Exception:
                    errors["base"] = "cannot_connect"
                else:
                    if not result or "auth_token" not in result:
                        errors["base"] = "unknown"
                    else:
                        data = {
                            "host": host,
                            "activation_key": activation_key,
                            "auth_token": result.get("auth_token"),
                            "client_id": result.get("client_id"),
                        }
                        return self.async_create_entry(
                            title=f"HomematicIP Local ({host})", data=data
                        )

        schema = vol.Schema(
            {
                vol.Required("host"): str,
                vol.Required("activation_key"): str,
                vol.Optional("existing_credentials", default=False): bool,
            }
        )
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

    async def async_step_credentials(
        self, user_input: dict[str, object] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        assert self._host is not None and self._activation_key is not None

        if user_input is not None:
            auth_token = str(user_input.get("auth_token", "")).strip()
            client_id: str | None = None
            try:
                client_id = await self.hass.async_add_executor_job(
                    confirm_auth_token, self._host, auth_token, self._activation_key
                )
            except Exception:
                client_id = None

            data = {
                "host": self._host,
                "activation_key": self._activation_key,
                "auth_token": auth_token,
                "client_id": client_id,
            }
            return self.async_create_entry(
                title=f"HomematicIP Local ({self._host})", data=data
            )

        schema = vol.Schema({vol.Required("auth_token"): str})
        return self.async_show_form(
            step_id="credentials", data_schema=schema, errors=errors
        )
