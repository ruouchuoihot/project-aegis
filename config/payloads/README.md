# API Payloads

These JSON files are reference request bodies for manual Kibana, Elasticsearch, and Fleet API calls.

They are kept out of the project root because the core runtime is `docker-compose.yml`, `Makefile`, `scripts/`, and `rules/`.

## Files

- `data_view.json`: Kibana data view for Aegis simulation logs.
- `kibana_security_settings.json`: broad Security App default index/data view settings.
- `force_security_settings.json`: minimal Security App settings for `logs-*` and simulation logs.
- `reset_security_settings.json`: reset payload for Security App default indices.
- `dv_security_settings.json`: older data-view-ID based Security App setting.
- `monitoring_settings.json`: Elasticsearch monitoring collection setting.
- `output_config.json`: Fleet default Elasticsearch output.
- `policy.json`, `policy_fs.json`, `policy_agent.json`: Fleet policy payloads.
- `fleet_server_package_policy.json`: Fleet Server integration package policy for `aegis-fleet-server`.
- `enrollment_token_agent.json`: request body for generating an enrollment token for `aegis-agent-policy`.
- `run_rules_create_alerts.json`: request body for running Aegis rules and creating lab-managed alerts.
- `data_view_aegis_alerts.json`: Kibana data view for the lab-managed `aegis-alerts-default` index.
- `native_rule_*.json`: Kibana Security Detection Engine rules for the Aegis simulator.
- `patch_rule_*_window.json`: small PATCH payloads for tuning rule lookback windows.
