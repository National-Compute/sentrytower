"""Shared values of the model gateway and of the processes that call it.

The gateway refuses a call at a run ceiling with HTTP 402, an error object
of the type ``BUDGET_ERROR_TYPE`` and a message that holds one of
``REFUSAL_TEXTS``. The funnel client reads the type; the agent runner and
the funnel read the message that the agent session records. The message
also holds "out of budget (quota exceeded)", so that the agent treats the
refusal as final and does not retry it.

The gateway also answers ``GET /budget`` with the money of the run
(``read_budget``): the engines read it before they start work, and no new
work starts when ``stop`` is true (85% of the cost cap is spent, or the
provider refused the run).

Standard library only: the funnel and the agent runner run in their own
processes and import this module.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

BUDGET_STATUS = 402
BUDGET_ERROR_TYPE = "sentrytower_budget_exhausted"
TOKEN_CEILING_TEXT = "token ceiling reached"
SPEND_CEILING_TEXT = "spend ceiling reached"
REFUSAL_TEXTS = (TOKEN_CEILING_TEXT, SPEND_CEILING_TEXT, BUDGET_ERROR_TYPE)
# The variable that holds the credential of the local gateway in the
# environment of the funnel and of each agent session. It never holds the
# provider key: the gateway holds that key and sends it upstream.
CREDENTIAL_VARIABLE = "OPENROUTER_API_KEY"
PLACEHOLDER_CREDENTIAL = "local-gateway-key"
BUDGET_PATH = "/budget"


def read_budget(base_url: str, credential: str | None = None, timeout: float = 5.0) -> dict[str, Any] | None:
    """The money of the run from the gateway at ``base_url`` (``GET /budget``), or None when it cannot be read.

    ``credential`` defaults to the credential of the run in the environment
    (``CREDENTIAL_VARIABLE``). A reader that gets None goes on as before: the
    gateway still refuses each call that the cap cannot hold.
    """
    token = credential or os.environ.get(CREDENTIAL_VARIABLE) or PLACEHOLDER_CREDENTIAL
    request = urllib.request.Request(base_url.rstrip("/") + BUDGET_PATH, headers={"authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            value = json.loads(response.read(65536))
    except (OSError, ValueError, urllib.error.URLError):
        return None
    return value if isinstance(value, dict) else None
