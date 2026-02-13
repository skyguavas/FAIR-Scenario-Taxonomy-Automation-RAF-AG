# RAF-AG-based-CTI-decomposition

This repo implements the first step of FAIR-aligned scenario automation: transforming raw, unstructured CTI text (AnnoCTR `text`) into:
(1) structurally normalized sentences (A-1) and 
(2) extracted event objects (A-2) that capture *who did what to what (and optionally how)*.

## 1. Overall Design

### 1.1 Goal
**Core Question**: Can unstructured CTI text be automatically transformed into a FAIR-aligned scenario structure (Threat / Asset / Method / Effect)?

### 1.2 Pipeline
**End-to-end flow**
1. **Input**: AnnoCTR dataset `text` field (raw CTI)
2.  **A-1 Text Normalization**: structural cleanup without changing meaning
3. **A-2 Event Extraction**: produce event objects per normalized sentence
4. **Outputs**:
   - `normalized.jsonl` (or `.csv`): sentence-level normalized text + IDs
   - `events.jsonl`: extracted events with provenance (`source_sentence_id`)

```text
Raw CTI text
   │
   ▼
A-1: Text Normalization  ──►  normalized sentences (stable structure)
   │
   ▼
A-2: Event Extraction     ──►  events: actor/action/object