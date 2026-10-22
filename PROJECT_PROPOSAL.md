# Project Proposal: AI-Powered SOC SIEM Alert Triage and Simulated Incident Response

## 1. Abstract

Security Operations Centers (SOCs) receive more alerts than analysts can investigate promptly. This project proposes a defensive prototype that ingests security-event data, normalizes and correlates alerts, and uses a retrieval-augmented language-model workflow to produce evidence-linked triage summaries. The system will present a risk estimate, relevant indicators, and MITRE ATT&CK context to an analyst. A response module will demonstrate containment decisions only against simulated assets or a local mock environment; it will not modify production firewalls, terminate real processes, or isolate real devices.

The prototype will be evaluated on labeled, publicly available intrusion-detection data and controlled synthetic events. Evaluation will measure detection and classification quality, evidence traceability, response safety, and processing latency. The project emphasizes analyst assistance rather than autonomous security decisions.

## 2. Problem Statement

Alert volume, inconsistent telemetry, and time-consuming context gathering can delay incident investigation. Analysts often need to correlate events from multiple sources and consult threat knowledge before deciding whether an alert warrants escalation. A language model may help summarize this information, but can also produce unsupported claims or unsafe recommendations if it is not constrained to retrieved evidence and human oversight.

This project addresses the problem by combining deterministic parsing and scoring with retrieval-grounded summaries and a human-reviewed, simulated response workflow. The system is intended as an educational prototype, not a replacement for a production SIEM, EDR, or qualified analyst.

## 3. Aim and Objectives

### Aim

Design, implement, and evaluate a prototype that assists SOC analysts with evidence-grounded alert triage and safe, simulated incident-response decisions.

### Objectives

1. Ingest selected structured or semi-structured security-event records and normalize them into a documented common schema.
2. Correlate related events into candidate incidents using transparent rules and configurable time windows.
3. Retrieve relevant defensive knowledge, such as selected MITRE ATT&CK technique descriptions, for incident context.
4. Generate concise incident summaries that distinguish observed facts from hypotheses and cite the underlying event identifiers and retrieved sources.
5. Calculate and display a risk score with an explanation of its contributing factors.
6. Provide analyst review and approval for any proposed response action.
7. Execute response demonstrations only in a mock or isolated lab environment, with audit logging and a safe no-op mode.
8. Evaluate the prototype against labeled data and document its limitations, privacy considerations, and risks.

## 4. Scope

### In scope

- Offline ingestion and replay of a selected dataset or synthetic event records.
- A documented normalized event schema and validation of incoming records.
- Rule-based event correlation and explainable risk scoring.
- Retrieval from a small, curated defensive knowledge base.
- LLM-generated triage summaries constrained to retrieved context and event evidence.
- A basic analyst interface or API for reviewing incidents and approving simulated actions.
- A mock response adapter that records actions against simulated hosts, IPs, or firewall state.
- An audit trail recording evidence, model output, analyst decisions, and simulated actions.
- Evaluation using reproducible test data and predefined metrics.

### Out of scope

- Connecting to a production SIEM, EDR, endpoint, identity provider, or firewall.
- Applying firewall rules to real networks or terminating processes on real hosts.
- Autonomous containment of real systems.
- Ingesting live threat feeds or untrusted external content as an operational dependency.
- Claiming that the prototype detects all attack types or provides production-grade security.
- Training a foundation model or making a clinical, legal, or other high-impact decision.

## 5. Proposed System

### 5.1 Data ingestion and normalization

The prototype will load records from a selected public dataset, such as CICIDS2018 or UNSW-NB15, subject to dataset access and license requirements. If the chosen data is flow-oriented rather than endpoint telemetry, the proposal will describe it accurately and will not represent it as Sysmon or EDR data. A small synthetic dataset may supplement the public data for scenarios that the selected dataset does not represent.

Each accepted event will be converted to a normalized structure with, as applicable:

- Event identifier, timestamp, source, and event category.
- Source and destination address or asset identifiers.
- Protocol and relevant event attributes.
- Dataset label, when supplied, kept separate from model-generated conclusions.
- Provenance fields linking the normalized event to its source record.

Input validation will reject malformed records explicitly. Dataset labels will be used for evaluation and will not be exposed to the triage workflow when doing so would leak the expected answer.

### 5.2 Correlation and risk scoring

Transparent rules will group events by configurable attributes and time windows. A risk score will combine documented factors such as event severity, frequency, and rule matches. The interface will show the factors contributing to the score; the score will be treated as a prioritization aid rather than a calibrated probability unless calibration is separately demonstrated.

### 5.3 Retrieval-grounded analysis

A curated local knowledge base will contain selected MITRE ATT&CK descriptions and other appropriately licensed defensive references. The retrieval component will return relevant passages with source identifiers. The language model will receive only the incident evidence and retrieved passages needed for the task.

The generated incident record will include:

- A short summary of observed activity.
- A distinction between directly observed facts and possible interpretations.
- Event identifiers supporting each key claim.
- Relevant retrieved knowledge-base references.
- A confidence or uncertainty statement that is not presented as a probability unless calibrated.
- Suggested analyst follow-up, with no unapproved execution.

If retrieval finds no useful context or the model response fails validation, the application will present the available deterministic evidence and an explicit status rather than inventing a result.

### 5.4 Analyst review and simulated response

The analyst will be able to review evidence, summary, risk factors, and proposed response. Approval will be required before a response demonstration. The response adapter will operate only on in-memory simulated assets or an isolated local mock service. It will record the requested action, target simulation identifier, approval, result, and timestamp.

The prototype will not contain credentials or integrations capable of affecting real infrastructure. Production integrations are explicitly excluded from this project.

### 5.5 Audit and privacy

The system will retain a trace from each summary to its source events and retrieved passages. Logs will avoid unnecessary personal data and secrets. Dataset use, retention, and redistribution will follow the dataset's license and course requirements. Any demo data will be synthetic or public and non-sensitive.

## 6. High-Level Architecture

```text
Public / synthetic event data
             |
             v
      Ingestion and validation
             |
             v
    Normalization and provenance
             |
             v
 Event correlation and risk scoring
             |
       +-----+------+
       |            |
       v            v
 Incident evidence  Curated knowledge base
       |            |
       +------v-----+
         Retrieval and
       constrained summary
             |
             v
      Analyst review interface
             |
       Approval required
             |
             v
     Simulated response adapter
             |
             v
      Audit and evaluation data
```

## 7. Proposed Technology

The implementation will use Python, with FastAPI for an API if a service interface is needed. Data parsing, validation, and correlation will use lightweight Python libraries. A local vector store such as FAISS or ChromaDB may be used if it is compatible with the selected data volume and environment. The LLM may be local or accessed through an approved course environment; the implementation will document its model, version, configuration, and data-handling implications.

The design will keep ingestion, correlation, retrieval, generation, and response simulation as separable components so that the prototype can be tested without enabling any real-world action. The final technology choices may be adjusted to available hardware, course constraints, and dataset format.

## 8. Methodology and Work Plan

| Phase | Activities | Deliverable |
|---|---|---|
| 1. Requirements and data selection | Confirm learning objectives, select dataset, review license and fields, define threat scenarios and safety boundaries | Requirements and data dictionary |
| 2. Ingestion and normalization | Implement loaders, validation, normalized schema, and source-record traceability | Tested ingestion module |
| 3. Correlation and scoring | Implement baseline rules, time-window grouping, explainable risk factors | Correlation and scoring module |
| 4. Knowledge retrieval | Curate defensive references, index them, and test retrieval relevance | Versioned local knowledge base |
| 5. Triage workflow | Build constrained prompt flow, output validation, evidence references, and analyst review | Triage API or interface |
| 6. Response simulation | Implement approval flow and mock-only response adapter with audit records | Safe response demonstration |
| 7. Evaluation | Run reproducible tests, compare baselines, measure metrics, investigate errors | Evaluation results |
| 8. Finalization | Document architecture, setup, limitations, ethical considerations, and demo procedure | Final report and demonstration |

## 9. Evaluation Plan

Evaluation will use a held-out subset of the selected labeled dataset where feasible, plus synthetic scenarios for workflow and safety tests. Data splits will be defined before model-assisted evaluation to reduce leakage. Results will be compared with at least one transparent baseline, such as the dataset's labels or a rule-only triage method, as appropriate to the selected dataset.

### Metrics

- **Classification:** precision, recall, F1-score, and confusion matrix for the defined classes.
- **Prioritization:** precision and recall among the highest-priority alerts, with the cutoff documented.
- **Retrieval:** relevance of retrieved references on a manually reviewed sample.
- **Evidence traceability:** proportion of generated factual claims linked to event identifiers or retrieved sources.
- **Summary quality:** rubric-based analyst or peer review for correctness, clarity, uncertainty handling, and usefulness.
- **Operational performance:** ingestion and triage latency on a documented test environment.
- **Safety:** all response tests target simulated assets; unauthorized or unapproved response attempts are rejected and audited.

Performance targets will be set after confirming the dataset, hardware, and baseline. Any numerical target in the final report will be reported with its test setup and limitations rather than generalized to production environments.

## 10. Safety, Ethics, and Limitations

- The project is defensive and uses public or synthetic data for offline analysis.
- All response actions are simulated; no real firewall, endpoint, or network control is connected.
- An analyst approval gate is mandatory, and model output cannot directly authorize an action.
- Model-generated statements may be incorrect. Evidence links, output validation, uncertainty language, and analyst review mitigate but do not eliminate this risk.
- Dataset labels may be incomplete, imbalanced, or tied to collection-specific assumptions. Metrics will be interpreted in that context.
- Threat knowledge may become outdated; the knowledge-base snapshot and sources will be recorded.
- Privacy-sensitive data will not be sent to an external model. If an external model is used, only approved non-sensitive data will be submitted and the provider's data-handling terms will be reviewed.
- The prototype is not suitable for production deployment or unsupervised incident response.

## 11. Expected Deliverables

1. A working prototype for offline event ingestion, correlation, triage, and analyst review.
2. A normalized event schema and documented dataset mapping.
3. A curated, source-attributed defensive knowledge base.
4. A mock-only incident-response demonstration with approval and audit logging.
5. Automated tests for parsing, correlation, output validation, approval enforcement, and simulation boundaries.
6. Reproducible evaluation results and a discussion of errors and limitations.
7. Setup instructions, architecture documentation, and a final capstone report or presentation.

## 12. Success Criteria

The project will be considered successful if:

- The selected dataset can be loaded and normalized with source provenance retained.
- Correlated incidents and risk factors are inspectable and reproducible.
- Generated summaries include supporting event references and clearly separate facts from interpretations.
- The workflow provides useful retrieved context or explicitly indicates when context is insufficient.
- Unapproved and real-world response actions cannot be executed through the prototype.
- Automated tests verify the principal behaviors and safety boundaries.
- Evaluation results include appropriate baselines, documented methodology, and an honest account of limitations.

## 13. Preliminary References

- MITRE ATT&CK, Enterprise Matrix and technique knowledge base: <https://attack.mitre.org/>
- Canadian Institute for Cybersecurity datasets, including CICIDS2018: <https://www.unb.ca/cic/datasets/>
- UNSW-NB15 dataset information: <https://research.unsw.edu.au/projects/unsw-nb15-dataset>

Dataset terms, attribution requirements, and source availability will be verified before use. This proposal is a project plan, not a claim that the listed systems, data, or integrations have already been implemented.
