# Project-Start Operator Summary

status: accepted

run_id: missed-call-recovery-project-start

## Artifacts

- acceptance_rubric: status= exists=true sha256=2f246012011d1432ffda5eb6f3a316bff37b1e6f02af3c5db2340fffff0906fb
  path: `/tmp/ao2-public-test/ao2/target/factory-project-run-smoke/20260528T150421Z/generated-project/rubrics/missed-call-recovery-project-start-acceptance-rubric.json`
- project_acceptance_review: status= exists=true sha256=945867518e7fcb271680aa1ac392758ad573fb60374c0355864dcd2dbc09dd47
  path: `/tmp/ao2-public-test/ao2/target/factory-project-run-smoke/20260528T150421Z/project-start/project-acceptance-review.json`
- project_plan: status= exists=true sha256=a087dbe237512451b5eaa9fd83eb708b0d804dc1680dc06231491bbc7235a134
  path: `/tmp/ao2-public-test/ao2/target/factory-project-run-smoke/20260528T150421Z/project-start/project-plan/project-plan.json`
- project_run: status= exists=true sha256=a911ab57770e71dd76f49d8bf772f2238afcb9cdbacfc65d353aff7e9e283e4e
  path: `/tmp/ao2-public-test/ao2/target/factory-project-run-smoke/20260528T150421Z/project-start/project-run/missed-call-recovery-project-start-factory-project-run.json`
- project_start_bundle: status= exists=true sha256=a17268d85cd7172f7fe812fcb9762d0026a32186f728b0432b18c4e6f18639b6
  path: `/tmp/ao2-public-test/ao2/target/factory-project-run-smoke/20260528T150421Z/project-start-handoff.tgz`
- project_start_bundle_verification: status=accepted exists=true sha256=c624de01211e1ce74fd3d46c0e2f410aa32568a2d1414a95b8fbb1c5bc0d933d
  path: `/tmp/ao2-public-test/ao2/target/factory-project-run-smoke/20260528T150421Z/factory-project-start-bundle-verification.json`
- release_review_package: status= exists=true sha256=2261873a9b10d1acb059a28773726bcf235b479806c0df56e0a4dd6545a8b5bf
  path: `/tmp/ao2-public-test/ao2/target/factory-project-run-smoke/20260528T150421Z/project-start/project-run/missed-call-recovery-project-start-release-review-package.tgz`

## Trust Boundary

- release_acceptance_owner: factory-v3 evaluator-closer
- control_plane_role: read_only_observer_after_signed_evidence
- control_plane_approves_release: false
- mutates_ao_artifacts: false
