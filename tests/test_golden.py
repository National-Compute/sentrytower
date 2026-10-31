"""The golden request fixtures: a change of a model request is a test failure.

Each fixture of ``tests/golden`` holds the model requests of one scenario,
byte for byte, and the commands and configuration files of its agent
sessions. The harness of the measured runs sent the same requests in the
same scenarios; its agent commands had no repository guard extension. Regenerate
a fixture only for a deliberate change (``python tests/golden.py --write``)
and say why in the change log.
"""

from __future__ import annotations

import hashlib
import json
from importlib import resources
from pathlib import Path

import pytest

from golden import SCENARIOS, golden_path, run_scenario

# The SHA-256 of each prompt file: the prompt files of the measured runs, byte for byte.
PROMPT_DIGESTS = {
    "agent-audit.txt": "d62c89fc372167cf85d714e41d9d696bcd76149ce140c1712a439d372ee4a568",
    # The prompts of a run of more than one standard run (the focus sessions and the slices); a standard run sends none.
    "agent-slice.txt": "456e308d446544e08836e3d242624eddf74e343226d65d59e0e3d504a5cce70b",
    "funnel-focus.txt": "dcc87e57f1b9859b906144ebeded911fe0ef37024919e768f0f179b00063d85c",
    "funnel-focus-lenses.txt": "25403123a5b9b7ef55dab05e73b7a24ee608f45497b5f02ea0391ba4d6726226",
    "agent-final.txt": "66e09e0cf05126c5d2b4c03178471d4dee21635d63af8a9494f5def8844c5208",
    "agent-findings.schema.json": "2f89706535e9f87133c1942520780e878f129b377e0e6e02e56e60ddf64db559",
    "agent-output.txt": "cc88ff679844c1c95e032aeaaa2456b2fc06e053d223d76abb0bd0dbb44258b6",
    "funnel-deep-check.txt": "9a15d705c96f357ec64481fa454f6533c18b48556ef8be2cec207a37d0942a35",
    "funnel-rating.txt": "28ae22eef5d1ee7a7997c056a98ac561e776fd6fd5a533ede633f9b12fec2839",
    "funnel-unit-check-system.txt": "a889a4b2d3323579774369d9d087312609fe0e9737c6503925576d71d076bc17",
    "funnel-unit-check.txt": "8996b5163b4cd117f28e6804631a0fb48c0dbc34d45f9088dcf2c718fb917208",
    "funnel-verify.txt": "ceaa2bcc813020fbd28bb03b2a1797cd780f0fcc5aafbe49ba7f9790ab924c31",
}


def test_the_prompt_files_are_the_pinned_prompt_files() -> None:
    folder = resources.files("sentrytower.prompts")
    found = {item.name: hashlib.sha256(item.read_bytes()).hexdigest() for item in folder.iterdir() if item.name.endswith((".txt", ".json"))}
    assert found == PROMPT_DIGESTS


@pytest.mark.slow
@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_the_model_requests_of_a_scenario_are_the_golden_requests(name: str, tmp_path: Path) -> None:
    expected = json.loads(golden_path(name).read_text(encoding="utf-8"))
    actual = run_scenario(name, tmp_path)
    assert actual["route"] == expected["route"]
    assert len(actual["requests"]) == len(expected["requests"])
    for index, (got, want) in enumerate(zip(actual["requests"], expected["requests"], strict=True)):
        assert got == want, f"request {index} of {name} changed"
    assert actual["agent_sessions"] == expected["agent_sessions"]
    assert actual["findings"] == expected["findings"]


def test_the_golden_requests_carry_the_measured_settings() -> None:
    requests = json.loads(golden_path("funnel-webapp").read_text())["requests"]
    for text in requests:
        request = json.loads(text)
        assert request["model"] == "z-ai/glm-5.3-flash" and request["temperature"] == 1.0
        assert request["reasoning"] == {"effort": "medium"} and request["max_completion_tokens"] == 131072
        # The provider route of the measured runs, and the data policy of the built-in routes.
        assert request["provider"] == {
            "allow_fallbacks": True,
            "data_collection": "deny",
            "only": ["z-ai/fp8", "atlas-cloud/fp8", "streamlake/fp8", "novita/fp8", "gmicloud/fp8"],
        }
        assert request["stream"] is True and request["stream_options"] == {"include_usage": True}
        # Canonical JSON: sorted keys, no spaces.
        assert text == json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
