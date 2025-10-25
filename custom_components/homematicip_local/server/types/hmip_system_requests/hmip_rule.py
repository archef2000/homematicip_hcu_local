from enum import Enum
from typing import TypedDict


class HomeRequestBodies:
    class EnableSimpleRule(TypedDict):
        ruleId: str
        "id of the automation in question"
        enabled: bool
        "Flag if the automation will be enabled or disabled"


class HomeRequestPaths(Enum):
    enableSimpleRule = "enableSimpleRule"
