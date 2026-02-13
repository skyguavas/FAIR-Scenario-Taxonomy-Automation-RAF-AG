# RAF-AG-based-CTI-decomposition

This repo implements the first step of FAIR-aligned scenario automation: transforming raw, unstructured CTI text (AnnoCTR `text`) into:  
(1) structurally normalized sentences (A-1) and  
(2) extracted event objects (A-2) that capture *who did what to what (and optionally how)*.  

## 1. Overall Design

### 1.1 Goal
**Core Question**:  
Can unstructured CTI text be automatically transformed into a FAIR-aligned scenario structure (Threat / Asset / Method / Effect) ?

### 1.2 Pipeline
**End-to-end flow**
1. **Input**:  
    AnnoCTR dataset `text` field (raw CTI)  
  
2.  **A-1 Text Normalization**:  
    Structural cleanup without changing semantics  
  
3. **A-2 Event Extraction**:  
    Produce event objects per normalized sentence  
  
4. **Outputs**:
   - `A1_results.json`: Sentence IDs + Raw text + Normalized text  
   - `A2_events.json`: extracted events with provenance (`source_sentence_id`)  

```text
Raw CTI text
   │
   ▼
A-1: Text Normalization  ──►  normalized sentences (stable structure)
   │
   ▼
A-2: Event Extraction     ──►  events: actor/action/object
```

### 1.3 Data Model
`A1_results.json` consists of normalized text sentences in the following form:  
```text
{
    "sentence_id": "...",
    "raw_text": "...",
    "normalized_text": "..."
}
```
  
`A2_events.json` consists of the following form:
```text
{
    "actor": null,
    "action": "harvest",
    "object": "user credentials",
    "source_sentence_id": "proofpoint_2021-05-18_threat-actors-exploit-microsoft-and__s0025"
  }
```
  
### 1.4 Execution
# Example
```text
python pipeline.py \
  --input data/raw/annoctr_train.json \
  --a1_out outputs/A1_results.json \
  --a2_out outputs/A2_events.json \
  --limit None
```


