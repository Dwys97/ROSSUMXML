# 🚀 FINAL CODE AGENT INSTRUCTION: ULTRA-LIGHTWEIGHT IDP REFACTORING

## 🎯 Project Goal
Refactor the document processing project into a modular, high-accuracy, **CPU-ONLY**, three-phase microservice architecture. The total application and model stack size must **NOT EXCEED 6 GB** to accommodate the Git Codespaces environment. The system must support a continuous Human-in-the-Loop (HITL) learning cycle via Label Studio.

## 1. Non-Negotiable Constraints
* **Disk Limit:** Total combined size of all models, dependencies, and code (excluding Label Studio/Redis data) **MUST BE UNDER 6 GB**.
* **Compute:** **STRICTLY CPU-ONLY INFERENCE.** GPU use is not permitted.
* **Optimization:** All ML components must be optimized for CPU using **ONNX Runtime** where applicable (e.g., for the NER model) and minimal base images (`-slim` or `alpine` Docker variants).
* **Accuracy Strategy:** Accuracy is achieved via **specialized fine-tuning** and robust **layout analysis**, NOT large general models.

## 2. Component Stack (The "Under 6GB" Solution)

| Phase | Component | Library/Model | Key Instruction |
| :--- | :--- | :--- | :--- |
| **P1: OCR & Layout** | **OCR Engine** | **PaddleOCR** (Lightest Inference Model) | Use the most compact model weights available. Must output text + high-fidelity bounding boxes. |
| | **Layout Analyzer** | `LayoutParser` + `PP-StructureV2` | Code-based libraries for table and block detection; rely on geometry, not large vision models. |
| **P2: Semantic Extraction** | **Extractor Model** | **GLiNER** (Sub-600MB version) | Load the small GLiNER model for highly flexible Named Entity Recognition (NER). Must be fine-tuned on custom data. |
| | **Runtime** | `ONNX Runtime` | Essential for loading and running the GLiNER/PaddleOCR models at max CPU speed. |
| **P3: HITL Orchestrator** | **API Gateway** | `FastAPI` | Manages the workflow, confidence scoring, and JSON validation (`Pydantic`). |
| | **Queue/Feedback** | `Redis` + `Label Studio` | Redis handles the queueing for HITL validation when confidence is low. |

## 3. Mandatory Implementation Tasks

### A. Code Structure and Data Flow
1.  **Modularization:** Create three separate services: `ocr_service`, `extractor_service`, and `api_gateway`.
2.  **Input Augmentation:** The `ocr_service` **MUST** augment the extracted text with spatial context (e.g., adding `[TABLE_ROW_START]` or `[HEADER_RIGHT]`) before sending it to the `extractor_service`. This replaces the visual input of LayoutLM.
3.  **Schema Validation:** Use **Pydantic** in the `api_gateway` to enforce a strict, standardized JSON output schema for customs data.

### B. Deployment Artifacts
1.  **`requirements.txt`:** Must be minimal, excluding large, unnecessary dev dependencies.
2.  **`Dockerfile`s (per service):** Use a minimal base image (e.g., `python:3.10-slim-buster`).
3.  **`docker-compose.yml`:** Define the five necessary containers: `ocr_service`, `extractor_service`, `api_gateway`, `label_studio`, and `redis`. Ensure all services are configured for CPU-only execution.
4.  **Model Scripts:** Provide a script to download and confirm the use of the **smallest available weights** for PaddleOCR and GLiNER.