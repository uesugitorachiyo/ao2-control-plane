import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "github-issue-intake-observation-v0.1.json"


def test_github_issue_intake_observation_stays_read_only():
    observation = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert observation["schema_version"] == "ao2.cp-github-issue-intake-observation.v0.1"
    assert observation["status"] == "observed"
    assert observation["observed_event"] == "github_issue_intake_classified"
    assert observation["current_public_pair"] == {
        "ao2": "v0.5.1",
        "control_plane": "v0.1.16",
    }
    intake = observation["issue_intake"]
    assert intake["state"] == "intake_validated"
    assert intake["command_policy_class"] == "safe_read_only_discovery"
    assert intake["github_read_performed"] is False
    assert intake["github_write_performed"] is False
    for state in [
        "intake_validated",
        "invalid_url",
        "unsupported_host",
        "policy_blocked",
        "security_sensitive",
    ]:
        assert state in observation["terminal_states_observed"]
    for action, value in observation["denied_actions"].items():
        assert value is False, f"{action} must remain denied"
    assert "do not open or merge" in observation["operator_next_action"]
