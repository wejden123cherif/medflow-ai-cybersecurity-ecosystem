# MedFlow Investigator / Executor Split

MedFlow is now separated into two logical components:

- **Investigator** (`medflow_investigator`): collects alerts, enriches IOCs, maps MITRE context, correlates events, predicts campaign stage, writes the investigation report, scores risk, resolves playbooks, proposes response actions, and runs the approval gate.
- **Executor** (`medflow_executor`): consumes the Investigator handoff, executes approved or acknowledged actions through response connectors, closes the incident, and handles SOC notification through the email connector.

The boundary between the components is the JSON-serializable `InvestigationHandoff` contract in `medflow_contracts`. It contains the approved, acknowledged, and rejected actions plus the incident context required by Executor. The contract is deliberately wire-safe so the current in-process call can later become a network call without redesigning the pipeline.

Current single-machine operation still runs both components locally:

```python
result = run_investigation(...)
execution = run_execution(result)
```

In a future distributed deployment, the Investigator can run where the Wazuh Manager and MedFlow investigation brain live. The Executor can run separately or remain local while its Firewall and IDS connectors reach the target VM over SSH using the existing remote execution layer. This split makes the two-VM topology possible without another structural refactor.
