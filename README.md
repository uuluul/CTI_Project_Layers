# Automated Threat Intelligence & Hybrid Defense System (Layer 1-5)

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![OpenSearch](https://img.shields.io/badge/OpenSearch-2.11-green)
![STIX 2.1](https://img.shields.io/badge/Standard-STIX%202.1-orange)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

## 📖 Project Overview

This project implements a **Next-Gen Automated CTI Defense System**. It leverages Large Language Models (LLMs) to transform unstructured Cyber Threat Intelligence (CTI) reports into structured STIX 2.1 objects and integrates with OpenSearch for a **Hybrid Detection Mechanism**.

The system is designed with a 5-Layer architecture:
* **Layer 1 & 2:** Automated CTI Extraction & STIX Conversion (LLM-based).
* **Layer 3:** Vector Database Storage (OpenSearch).
* **Layer 4:** Rule-Based Detection (Known Threats).
* **Layer 5:** Semantic Anomaly Detection (Unknown Threats via Vector Search).

## 🏗 System Architecture

![Architecture Diagram](images/CTI_image.png)
*(This diagram visualizes the logic within `src/run_pipeline.py`)*

## ✨ Key Features

1.  **Unstructured to Structured**: Automatically parses natural language CTI reports (PDF/TXT) into validated STIX 2.1 JSON bundles using OpenAI/Azure GPT models.
2.  **Vector Database Integration**: Ingests system logs and calculates embeddings for semantic search using OpenSearch k-NN.
3.  **Hybrid Detection Engine**:
    * **Rule-Based**: Matches logs against CTI Indicators (IPs, Domains, Hashes).
    * **Adaptive Semantic Anomaly Detection**: 
        * **Algorithm**: Uses Cosine Similarity on HNSW indexes (Nmslib) for high-dimensional vector analysis.
        * **Dynamic Calibration**: Automatically calculates **P95 thresholds** based on statistical distribution of baseline logs, removing the need for manual tuning.
        * **Cost-Efficient**: Optimizes vector retrieval to minimize LLM API usage during calibration.
4.  **Automated Pipeline**: End-to-end flow from report ingestion to threat alert generation.

## 🛡️ Deep Dive: Layer 5 Anomaly Detection

This module implements a "Zero-Day" detection mechanism using **Unsupervised Learning**. It identifies threats based on semantic deviation rather than static signatures.

### 1. Core Algorithms
* **Vector Space Model**: Utilizes **OpenAI `text-embedding-3-small`** (1536 dimensions) to convert unstructured logs into semantic vectors.
* **Cosine Similarity**: Adopts Cosine Similarity instead of L2 distance to strictly measure the "directional" (contextual) difference, ensuring robustness against log length variations.
* **HNSW Indexing**: Leverages **OpenSearch k-NN** (Nmslib engine) for millisecond-level retrieval.

### 2. Adaptive Threshold Calibration (P95)
Instead of a hardcoded threshold, the system automatically learns from the environment:
1.  **Sampling**: Randomly selects baseline logs ($N=50 \sim 200$) using `function_score`.
2.  **Self-Exclusion k-NN**: Finds $K$ nearest neighbors ($K=5$) for each sample, strictly **excluding itself** to prevent data leakage.
3.  **Statistical Logic**:
    > "If a new log is more different than **95% (P95)** of known normal logs, it is an anomaly."

### 3. Optimization
* **Vector Reuse**: Retrieves pre-calculated vectors directly from OpenSearch during calibration, reducing LLM API costs and latency by **~90%**.

## 🚀 Installation & Setup

### 0. Prerequisites (System Preparation)

* **Python 3.10+**
* **Docker & Docker Compose**

<details>
<summary><strong>🐧 Ubuntu/Linux Users: Click here for Docker Installation Guide</strong></summary>

If you haven't installed Docker yet, run these commands:

```bash
# 1. Add Docker's official GPG key
sudo apt-get update
sudo apt-get install ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# 2. Add the repository to Apt sources
echo \
"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
$(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# 3. Install Docker packages
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```
</details>

1.  **Clone the repository**
    ```bash
    git clone https://github.com/uuluul/CTI_Project_Layers.git
    cd CTI_Project_Layers
    ```

2.  **Set up Virtual Environment**

    *Note: Ubuntu users note: You may need to install the venv package first: sudo apt install python3.10-venv*

    ```bash
    python -m venv .venv
    source .venv/bin/activate  # Mac/Linux
    # .venv\Scripts\activate   # Windows
    ```

3.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Environment Configuration**

    *Note: Create a `.env` file based on `.env.example`:*

    ```bash
    cp .env.example .env
    # Edit .env and input your API Keys
    ```

5.  **Start Database**

    *Note: ⚠️ Important for Linux Users: OpenSearch requires increased memory map limits. If you skip this, the container may crash (Exit Code 137).*

    ```bash
    # 1. Set memory limit (Linux only)
    sudo sysctl -w vm.max_map_count=262144

    # 2. Start containers

    # Note: Use sudo if your user is not in the docker group
    
    sudo docker compose up -d
    ```

### 1. Initialize OpenSearch Index (Layer 3)
Set up the vector index in OpenSearch.
```bash
python -m src.setup_opensearch
```
### 2. Ingest Baseline Logs
Simulate normal system behavior by ingesting logs into the vector database.
```bash
python -m src.ingest_logs
```
### 3. Run CTI Pipeline (Layer 1 & 2)
Start the automated pipeline service. The system will continuously monitor the `data/input/` directory for new CTI reports.
```bash
python -m src.run_pipeline
```

How to use:

1. Keep the terminal running (Service Mode).
2. Drop any .txt CTI report into the data/input/ folder.
3. The system automatically processes it:
    Success: Moves file to data/processed/ and generates STIX objects in out/.
    Failure: Moves file to data/error/ for review.

### 4. Run Detection (Layer 4 & 5)
Check for known indicators (Rules) and unknown anomalies (AI).
```bash
# Rule-based detection
python -m src.detect_rules
# Semantic anomaly detection
python -m src.detect_anomaly
```

## 📂Project Structure (專案結構)
```Plaintext
├── data/
│   ├── input/          # 📥 Drop new .txt reports here
│   ├── processed/      # ✅ Successfully processed files
│   ├── error/          # ❌ Failed files (for debugging)
│   └── sample_cti.txt  # Backup sample
├── out/                # Generated STIX JSON bundles & Reports
├── src/
│   ├── run_pipeline.py    # Main Automation Service (Daemon)
│   ├── detect_rules.py    # Layer 4: Exact match detection
│   ├── detect_anomaly.py  # Layer 5: Vector-based detection
│   ├── ingest_logs.py     # Log ingestion & embedding
│   └── to_stix.py         # STIX 2.1 object builder
├── docker-compose.yml  # OpenSearch (v2.11.1)
└── requirements.txt    # Python dependencies
```

## 🔮 Future Roadmap & Production Considerations

To scale this project for enterprise production environments, the following architecture upgrades are recommended:

* **Log Collector**: Replace the Python ingestion script with **Fluent Bit** or **Data Prepper** for high-throughput, reliable log streaming.
* **Cluster Scalability**: Deploy OpenSearch in a multi-node cluster architecture (3+ nodes) for high availability.
* **Hybrid Anomaly Detection**:
    * Use **OpenSearch Anomaly Detection (Random Cut Forest)** for time-series anomalies (e.g., CPU spikes, traffic surges).
    * Keep **Layer 5 (Vector Search)** specifically for *semantic* anomalies (e.g., obfuscated command lines, social engineering context), which traditional statistical detectors cannot capture.