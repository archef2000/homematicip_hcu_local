from enum import Enum
from typing import TypedDict


class HomeSecurityRequestBodies:
    class SetZonesActivation(TypedDict):
        zonesActivation: dict[str, bool]
        """
        A map for functional zone identifier to activation state
        `"EXTERNAL": true,
        "INTERNAL": true`
        """

    class SetExtendedZonesActivation(SetZonesActivation):
        ignoreLowBat: bool
        "Determines if lowbat should be ignored"


class HomeSecurityRequestPaths(Enum):
    acknowledgeSafetyAlarm = "acknowledgeSafetyAlarm"
    "Acknowledges the safety alarm"
    setExtendedZonesActivation = "setExtendedZonesActivation"
    "Set the extended activation state for one or more security zones"
    setZonesActivation = "setZonesActivation"
    "Set the activation state for one or more security zones"


# acknowledgeSafetyAlarm =
# setExtendedZonesActivation = SetExtendedZonesActivation
# setZonesActivation = SetZonesActivation
