import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "github-issue-authenticity-observation-v0.1.json"


def test_github_issue_authenticity_observation_tracks_truth_set_and_denies_actions():
    observation = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert observation["schema_version"] == "ao2.cp-github-issue-authenticity-observation.v0.1"
    assert observation["status"] == "observed"
    assert observation["current_public_pair"] == {
        "ao2": "v0.5.1",
        "control_plane": "v0.1.16",
    }
    truth = observation["truth_set"]
    assert truth["fixture_count"] == 13
    assert truth["authentic_bug_count"] == 2
    assert truth["non_bug_count"] == 11
    assert truth["precision"] >= 0.95
    assert truth["recall"] >= 0.90
    states = set(observation["terminal_states_observed"])
    for state in [
        "authentic_bug_deterministic",
        "authentic_bug_flaky_measured",
        "cannot_reproduce",
        "policy_blocked",
        "security_routing_required",
        "untrusted_instruction_ignored",
    ]:
        assert state in states
    reproduction = observation["reproduction"]
    assert reproduction["failing_pre_patch_reproduction_required"] is True
    assert reproduction["negative_controls_required"] is True
    assert reproduction["flaky_cases_require_repeated_runs"] is True
    assert reproduction["uncertainty_promoted_to_authentic_without_measurement"] is False
    for action, value in observation["denied_actions"].items():
        assert value is False, f"{action} must stay denied"
