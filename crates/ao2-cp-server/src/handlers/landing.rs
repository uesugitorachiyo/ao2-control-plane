use axum::{
    http::{header, StatusCode},
    response::IntoResponse,
};

pub async fn landing_page() -> impl IntoResponse {
    let html = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AO2 Control Plane</title>
  <style>
    :root {
      color-scheme: light;
      --ink: #17201b;
      --muted: #56635d;
      --line: #cfd8d3;
      --surface: #f7f8f5;
      --panel: #ffffff;
      --accent: #0b6b4f;
      --warn: #8a4b00;
    }
    body {
      margin: 0;
      font-family: ui-serif, Georgia, Cambria, "Times New Roman", serif;
      background: var(--surface);
      color: var(--ink);
    }
    main {
      max-width: 64rem;
      margin: 0 auto;
      padding: 3rem 1.25rem;
    }
    h1 {
      margin: 0 0 .5rem;
      font-size: clamp(2rem, 5vw, 4rem);
      line-height: .95;
      letter-spacing: 0;
    }
    h2 {
      margin: 0 0 .75rem;
      font-size: 1.05rem;
      text-transform: uppercase;
      letter-spacing: .08em;
    }
    p {
      max-width: 46rem;
      color: var(--muted);
      font-size: 1.05rem;
      line-height: 1.55;
    }
    code {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      overflow-wrap: anywhere;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(16rem, 1fr));
      gap: 1rem;
      margin-top: 2rem;
    }
    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 1rem;
    }
    ul {
      margin: 0;
      padding-left: 1.1rem;
      line-height: 1.75;
    }
    a {
      color: var(--accent);
      font-weight: 700;
    }
    .notice {
      border-left: 4px solid var(--warn);
      padding-left: 1rem;
    }
  </style>
</head>
<body>
  <main>
    <h1>AO2 Control Plane</h1>
    <p>Local read-only observer for signed AO2 evidence, memory exports, release posture, and Phase 1 promotion status. This page is public and intentionally does not render secrets.</p>
    <section class="grid" aria-label="Operator links">
      <div class="panel">
        <h2>Public Checks</h2>
        <ul>
          <li><a href="/healthz">/healthz</a></li>
          <li><a href="/readyz">/readyz</a></li>
        </ul>
      </div>
      <div class="panel">
        <h2>Dashboards</h2>
        <ul>
          <li><a href="/api/v1/phase1/promotion/dashboard">Phase 1 Promotion</a></li>
          <li><a href="/api/v1/storage/dashboard">Storage</a></li>
          <li><a href="/api/v1/audit-log/dashboard">Audit Log</a></li>
          <li><a href="/api/v1/evidence-pack/dashboard">Signed Evidence</a></li>
        </ul>
      </div>
      <div class="panel">
        <h2>API Discovery</h2>
        <ul>
          <li><a href="/api/v1/control-plane/routes.json">Route Index JSON</a></li>
          <li><a href="/api/v1/status">Status JSON</a></li>
        </ul>
      </div>
    </section>
    <section class="panel notice" aria-label="Authentication note">
      <h2>Authentication</h2>
      <p>Authenticated dashboards require an <code>Authorization: Bearer</code> header. Do not put bearer tokens in browser URLs. Use a local client, extension, or CLI that injects the header from an environment variable such as <code>AO2_CP_API_TOKEN</code>.</p>
      <p>For normal browser review, run <code>python3 scripts/cp_dashboard_snapshot.py --base-url http://127.0.0.1:18745 --out-dir target/cp-dashboard-snapshots/latest --open</code>. The helper reads <code>AO2_CP_API_TOKEN</code>, fetches dashboards with an HTTP header, and opens local token-free snapshots.</p>
    </section>
    <section class="panel" aria-label="Trust boundary">
      <h2>Trust Boundary</h2>
      <p>AO2 Control Plane observes evidence only. It does not approve releases, start providers, mutate AO artifacts, or replace factory-v3 evaluator-closer acceptance.</p>
    </section>
  </main>
</body>
</html>"#;
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
}
