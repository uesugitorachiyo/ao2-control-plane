import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "github-issue-month3-repair-observation.json"


def test_month3_repair_observation_is_read_only_and_digest_clean():
    observation = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert observation["schema_version"] == "ao2.cp-github-issue-month3-repair-observation.v0.1"
    assert observation["status"] == "observed"
    assert observation["source_evidence_schema"] == "ao2.github-issue-month3-repair-evidence.v0.1"
    assert observation["current_public_pair"] == {
        "ao2": "v0.5.1",
        "control_plane": "v0.1.16",
    }

    repair = observation["repair_state"]
    for key in [
        "pre_patch_failed_expected",
        "post_patch_verified",
        "rollback_exact_state_restored",
        "replay_digest_match",
        "resume_without_duplicate_edits",
        "archive_public_safe",
    ]:
        assert repair[key] is True, f"repair_state.{key} must be true"

    readback = observation["operator_readback"]
    assert readback["feature_generated_draft_pr_opened"] is False
    assert readback["issue_write_performed"] is False

    for action, value in observation["denied_actions"].items():
        assert value is False, f"{action} must remain denied"
