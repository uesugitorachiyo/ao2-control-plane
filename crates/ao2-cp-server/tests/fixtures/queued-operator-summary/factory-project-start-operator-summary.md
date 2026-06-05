# Project-Start Operator Summary

status: accepted

run_id: missed-call-recovery-project-queued

## Artifacts

- acceptance_rubric: status= exists=true sha256=3accce21a784c18dc05e8327002896f4062767779a17c850e505d27bcbc6a044
  path: `/tmp/ao2-public-test/ao2/target/factory-project-run-smoke/20260528T153334Z/queued-generated-project/rubrics/missed-call-recovery-project-queued-acceptance-rubric.json`
- project_acceptance_review: status= exists=true sha256=3dbdb3c5d4c7a79f84d9244f696bf0775a1d03fe1cf3fc8b61b5035fdde2c44c
  path: `/tmp/ao2-public-test/ao2/target/factory-project-run-smoke/20260528T153334Z/queued-project-start/project-acceptance-review.json`
- project_plan: status= exists=true sha256=20c0fb88bfe5524d5134327fc213cec0feb564c023762368e496f92555eac2a3
  path: `/tmp/ao2-public-test/ao2/target/factory-project-run-smoke/20260528T153334Z/queued-project-start/project-plan/project-plan.json`
- project_run: status= exists=true sha256=3f9be5f396b97f7a027637babbd4dbb12b0b72a627f087168ab7e33362c8efd6
  path: `/tmp/ao2-public-test/ao2/target/factory-project-run-smoke/20260528T153334Z/queued-project-start/project-run/missed-call-recovery-project-queued-factory-project-run.json`
- project_start_bundle: status= exists=true sha256=0f1818dda08438ec67e04a94285e1fb13c3a0eea1fbdbda6f2328c981c9090e6
  path: `/tmp/ao2-public-test/ao2/target/factory-project-run-smoke/20260528T153334Z/queued-project-start/project-start-handoff.tgz`
- project_start_bundle_verification: status=accepted exists=true sha256=30edec455a2e51c3386d0d6eb2074624c904eca21b08f6a4da5f5556bcb0441c
  path: `/tmp/ao2-public-test/ao2/target/factory-project-run-smoke/20260528T153334Z/queued-project-start/factory-project-start-bundle-verification.json`
- release_review_package: status= exists=true sha256=dd46114be831b7f04e49d260d1d3006e5e5245646d5fb89b8d551d92d3a08e4a
  path: `/tmp/ao2-public-test/ao2/target/factory-project-run-smoke/20260528T153334Z/queued-project-start/project-run/missed-call-recovery-project-queued-release-review-package.tgz`

## Trust Boundary

- release_acceptance_owner: factory-v3 evaluator-closer
- control_plane_role: read_only_observer_after_signed_evidence
- control_plane_approves_release: false
- mutates_ao_artifacts: false
