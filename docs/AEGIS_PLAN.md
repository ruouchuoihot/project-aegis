# Project Aegis: Next-Generation SOC & Threat Hunting Lab Architecture

## 1. Executive Summary
Project Aegis is a modern, modular Security Operations Center (SOC) and Threat Hunting home lab. Inspired by the principles of The Hunting ELK (HELK), it departs from legacy architecture (ELK 7.x, Logstash, Spark) in favor of a lean, high-performance Elastic 8.x foundation. It is specifically designed to be "AI-Ready," incorporating modern ingestion, native detection, and the foundational elements required for future integration of LLM-based autonomous agents and Model Context Protocol (MCP) servers.

## 2. Architectural Differences: Aegis vs. HELK

| Feature | Legacy HELK | Project Aegis (New Lab) |
| :--- | :--- | :--- |
| **Core Stack** | Elastic 7.x (No TLS by default) | Elastic 8.x (Native Security, TLS, RBAC) |
| **Ingestion** | Logstash + Winlogbeat/Filebeat | **Fleet Server + Elastic Agent** (Centralized management) |
| **Buffering** | Kafka & Zookeeper | **Elasticsearch Data Streams** (Leaner, native buffering) |
| **Alerting** | ElastAlert (3rd Party) | **Elastic Native Detection Engine** (Kibana rules) |
| **Data Science** | Spark + Jupyter Notebooks | **Elastic Native ML + Future AI/MCP integration** |
| **Resource Profile**| Heavy (Requires 8GB+ RAM) | **Lean & Scalable** (Runs comfortably on 4-6GB initially) |

## 3. Core Components

### 3.1 Data Ingestion & Management
*   **Elastic Agent:** A single, unified agent deployed to endpoints (Windows/Linux) to collect logs, metrics, and security data.
*   **Fleet Server:** Centralized management console within Kibana to deploy policies, update agents, and manage integrations without touching YAML files on endpoints.

### 3.2 Storage & Search (The SIEM)
*   **Elasticsearch (8.x):** The core datastore, utilizing Data Streams for efficient time-series log storage and optimized for vector search (KNN) to support future AI semantic queries.
*   **Kibana (8.x):** The visualization and management UI, serving as the analyst's primary dashboard.

### 3.3 The "AI-Ready" Foundation
While the initial build focuses on a functional SIEM, the architecture is designed for AI integration:
*   **Vector Search Ready:** Elasticsearch 8.x supports native vector search, allowing logs to be embedded and searched semantically by an LLM.
*   **Model Context Protocol (MCP):** The lab will expose an API layer/service that acts as an MCP server. This allows AI agents (like Claude or custom LangChain agents) to query the SIEM, retrieve context, and propose hunting queries safely.
*   **Native ML:** Utilizing Elastic's built-in anomaly detection for traditional Machine Learning tasks (e.g., detecting unusual process executions or rare DNS queries) without needing a separate Spark cluster.

### 3.4 Attack Simulation (The Target Environment)
*   **Enhanced Event Generator:** A Python-based generator (expanding on the existing script) to inject realistic, MITRE ATT&CK mapped scenarios directly into Elasticsearch for immediate training.
*   **Vulnerable Endpoint (Future Phase):** A Windows or Linux container pre-configured to accept Atomic Red Team tests to generate real endpoint telemetry.

## 4. Phased Implementation Plan

### Phase 1: Foundation (The Lean SIEM)
*   Create a modern `docker-compose.yml` deploying Elasticsearch 8.x and Kibana with security enabled (HTTPS, passwords).
*   Implement automatic setup scripts (similar to `Makefile` targets) for generating certificates and configuring initial passwords.

### Phase 2: Fleet & Data Ingestion
*   Add Fleet Server to the Docker Compose network.
*   Automate the bootstrapping of Fleet and the generation of enrollment tokens.
*   Deploy a local Elastic Agent container to collect host metrics and prove the pipeline works.

### Phase 3: Detection Engineering & Simulation
*   Upgrade the `generate_events.py` script to simulate complex attacks (e.g., Ransomware behavior, C2 beacons).
*   Create and import a set of Kibana Detection Rules (Saved Objects) designed to catch the simulated attacks.

### Phase 4: The AI Gateway (Future Proofing)
*   Develop a basic Python API (FastAPI) that sits alongside Kibana.
*   Configure this API as an MCP server, allowing an external AI agent to authenticate and query Elasticsearch using natural language translated into KQL.
*   Enable Elastic's native ML jobs for anomaly detection.

## 5. Phase 5: Advanced Analytics Layer (The "Power" Module)
To match and exceed the capabilities of legacy platforms like HELK, Aegis includes an optional High-Scale Analytics layer:
*   **Vector Database (Qdrant):** A dedicated, high-performance vector store for managing long-term AI memory and security embeddings.
*   **Apache Spark 3.5:** Re-introduced for complex data engineering, large-scale log enrichment, and preparing datasets for LLM training.
*   **Unified AI Context:** The AI Gateway is upgraded to bridge data between Elasticsearch (hot logs) and Qdrant (long-term security knowledge).

## 6. Summary of Vision
Project Aegis aims to be the bridge between traditional threat hunting and AI-augmented security operations. By starting with a clean, modern Elastic 8.x foundation, it ensures that your home lab is not just a tool for today, but a research platform for the future of autonomous defense.
