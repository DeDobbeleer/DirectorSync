DirectorSyncV3/
├── docs/
│   ├── ARCHITECTURE.md
│   ├── MigrationPlan.md
│   ├── YAML_SPEC.md
│   ├── TRANSFORMERS.md
│   ├── V3_Predesign_Repos_and_RoutingPolicies.md
│   └── DATA_MODEL.md
│
├── lp_sync/
│   ├── **init**.py
│   ├── cli.py
│   ├── core/
│   │   ├── sync_engine.py
│   │   ├── desired_state_loader.py
│   │   ├── current_state_loader.py
│   │   ├── diff_engine.py
│   │   ├── apply_engine.py
│   │   ├── transformer_pipeline.py
│   │   ├── resource_profile.py
│   │   ├── director_client.py
│   │   └── exceptions.py
│   │
│   ├── transformers/
│   │   ├── base.py
│   │   ├── generic/
│   │   │   ├── validate_required.py
│   │   │   ├── normalize_lists.py
│   │   │   ├── coerce_types.py
│   │   │   ├── jinja_render.py
│   │   │   └── resolve_references.py
│   │   ├── repos/
│   │   │   ├── normalize_hiddenrepopath.py
│   │   │   ├── normalize_repoha.py
│   │   │   └── verify_repo_paths.py
│   │   ├── routing_policies/
│   │   │   ├── classify_lines.py
│   │   │   ├── build_routing_criteria.py
│   │   │   └── apply_repo_aliases.py
│   │   └── alert_rules/   # later
│   │
│   ├── profiles/
│   │   ├── repos.yml
│   │   ├── routing_policies.yml
│   │   └── alert_rules.yml
│   │
│   └── utils/
│       ├── db.py
│       ├── logging.py
│       └── helpers.py
│
├── tests/
│   ├── test_sync_engine.py
│   ├── test_transformers.py
│   └── examples/
│
├── db/
│   ├── schema.sql
│   ├── migrations/
│   └── seeds/
│
├── scripts/
│   ├── load_xlsx_into_db.py
│   └── export_state.py
│
├── pyproject.toml
└── README.md