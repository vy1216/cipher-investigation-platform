# CIPHER Final Validation Report

## Scope
Final package built from the latest Render + Vercel CIPHER codebase after the recurring Supabase/PostgreSQL 500s.

## Fixes included
- PostgreSQL `RealDictCursor`-safe ID handling in the database adapter.
- Corrected case creation using `INSERT ... RETURNING *` on PostgreSQL.
- Corrected PostgreSQL GIS queries that previously relied on SQLite-style GROUP BY behavior.
- Additive PostgreSQL/Supabase schema reconciliation for existing older CIPHER tables.
- Best-effort identity/serial sequence resynchronization.
- Frontend case creation waits for backend confirmation before updating active case state.
- Real database case ID is stored after successful creation.
- Evidence upload uses PostgreSQL `RETURNING *` and the Supabase Storage adapter.
- Supabase Storage health endpoint and descriptive storage errors.
- `showNetworkToast` compatibility export and removal of unsupported Cytoscape shadow style properties.
- Render web service + durable evidence worker configuration retained.
- Environment templates now include Supabase, CORS, and worker settings.

## Validation performed in the build environment
- Python compilation: PASS
- Frontend JavaScript syntax (`node --check`): PASS
- Static frontend/backend route contract: PASS (145 backend route shapes; 19 frontend fetch paths; 0 missing)
- PostgreSQL adapter regression test with RealDict-style rows: PASS
- Local end-to-end smoke test: PASS
- Core case creation + GIS + entity creation + relationship creation + graph retrieval: PASS

## Important limitation
A live Supabase PostgreSQL/Storage integration test was not possible in this build environment because the user's external credentials and network access are not available here. The package therefore includes the production fixes and offline/local regression coverage, but the final live Supabase check must be performed with the user's own environment variables.
