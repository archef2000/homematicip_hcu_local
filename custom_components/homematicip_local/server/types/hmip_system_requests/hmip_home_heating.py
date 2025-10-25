from enum import Enum
from typing import TypedDict


class _TemperatureRequestBody(TypedDict):
    temperature: float
    "The temperature that should be used during vacation mode Constraints: 5.0 to 30.0"


class HomeHeatingRequestBodies:
    class ActivateAbsenceWithDuration(TypedDict):
        duration: int
        "The amount of minutes that the economy mode should be activated"

    class ActivateAbsenceWithPeriod(TypedDict):
        endTime: str
        "The end time of the economy mode Constraints: yyyy_MM_dd HH:mm"

    class ActivateAbsenceWithFuturePeriod(ActivateAbsenceWithPeriod):
        startTime: str
        "The start time of the economy mode Constraints: yyyy_MM_dd HH:mm"

    class ActivateFutureVacation(
        ActivateAbsenceWithFuturePeriod, _TemperatureRequestBody
    ):
        pass

    class ActivateVacation(ActivateAbsenceWithPeriod, _TemperatureRequestBody):
        pass

    class SetCooling(TypedDict):
        cooling: bool
        "Flag that determines whether the cooling should be enabled or deactivated"


class HomeHeatingRequestPaths(Enum):
    activateAbsencePermanent = "activateAbsencePermanent"
    "Activate the economy mode"
    activateAbsenceWithDuration = "activateAbsenceWithDuration"
    "Activate the economy mode for the given amount of minutes"
    activateAbsenceWithFuturePeriod = "activateAbsenceWithFuturePeriod"
    "Activate the economy mode for the given period"
    activateAbsenceWithPeriod = "activateAbsenceWithPeriod"
    "Activate the economy mode for the given period"
    activateFutureVacation = "activateFutureVacation"
    "Activate the vacation mode"
    activateVacation = "activateVacation"
    "Activate the vacation mode"
    deactivateAbsence = "deactivateAbsence"
    "Deactivate the economy mode"
    deactivateVacation = "deactivateVacation"
    "Deactivate the vacation mode"
    setCooling = "setCooling"
    "Activate or deactivate the cooling mode"


# activateAbsenceWithDuration = ActivateAbsenceWithDuration
# activateAbsenceWithFuturePeriod = ActivateAbsenceWithFuturePeriod
# activateAbsenceWithPeriod = ActivateAbsenceWithPeriod
# activateFutureVacation = ActivateFutureVacation
# activateVacation = ActivateVacation
# deactivateAbsence =
# deactivateVacation =
# setCooling = SetCooling
