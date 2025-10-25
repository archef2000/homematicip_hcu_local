from enum import Enum


class HmIPHomeRequestPaths(Enum):
    checkAuthToken = "checkAuthToken"
    "Check if an AuthToken is still valid for a client on a server. Use case: Check if a client still has a valid token in a multi HAP environment (multiple HAPs / installations are paired via app)"
    getState = "getState"
    "Get the state of the home"
    getStateForClient = "getStateForClient"
    "Get the state that is relevant for the requesting (smart watch) client"
    getSystemState = "getSystemState"
    "Get the current state of the system"
