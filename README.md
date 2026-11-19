\# Adaptive Agentic Security Operations Center (SOC) Framework



\## Overview



The Adaptive Agentic SOC Framework is an AI-powered security operations system designed to automate and support security alert investigation, threat intelligence analysis, alert correlation, risk assessment, and response verification.



The framework uses specialized AI agents coordinated through a workflow to analyze security alerts and provide structured findings.



\## Key Features



\- Dataset-based security alert generation

\- Security event preprocessing

\- Adaptive alert routing

\- Multi-agent security investigation

\- Threat intelligence analysis

\- Alert correlation

\- Risk assessment and response recommendations

\- Verification of agent findings

\- Knowledge retrieval using Retrieval-Augmented Generation (RAG)



\## Agent Architecture



1\. \*\*Investigation Agent:\*\* Examines alert evidence and identifies suspicious activity.

2\. \*\*Threat Intelligence Agent:\*\* Analyzes indicators and retrieves relevant threat knowledge.

3\. \*\*Alert Correlation Agent:\*\* Identifies relationships between security alerts.

4\. \*\*Risk and Response Agent:\*\* Assesses risk and recommends response actions.

5\. \*\*Verification Agent:\*\* Reviews findings and checks the consistency of results.



\## Technology Stack



\- Python

\- FastAPI

\- LangChain

\- LangGraph

\- Retrieval-Augmented Generation (RAG)

\- Vector database

\- Pytest



\## Project Structure



\- `app/agents/` – Specialized security agents

\- `app/alert\_generation/` – Alert generation and severity logic

\- `app/api/` – API routes

\- `app/config/` – Application configuration

\- `app/dataset/` – Dataset loading

\- `app/orchestration/` – Workflow and adaptive routing

\- `app/preprocessing/` – Data preprocessing

\- `app/rag/` – Knowledge ingestion and retrieval

\- `app/schemas/` – Data models

\- `app/storage/` – Data persistence

\- `scripts/` – Utility scripts

\- `tests/` – Automated tests



\## Running the Application



Install the project dependencies:



```bash

pip install -r requirements.txt

```



Start the FastAPI application:



```bash

uvicorn app.main:app --reload

```



Open the API documentation at:



`http://127.0.0.1:8000/docs`



\## Running Tests



```bash

pytest

```



\## Project Goal



The goal is to develop an adaptive, agent-based SOC framework that improves security alert analysis by combining specialized agents, threat intelligence, knowledge retrieval, and structured response verification.

