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
**Example**
```text
python pipeline.py \
  --input data/raw/annoctr_train.json \
  --a1_out outputs/A1_results.json \
  --a2_out outputs/A2_events.json \
  --limit None
```

## 2. A-1: Text Normalization
### 2.1 Design Intent
A-1’s purpose is to make raw CTI text *structurally stable* so that downstream event extraction (A-2) can operate on sentences with fewer formatting artifacts and less layout-driven ambiguity.  

Concretely, A-1 aims to:  
- **Reduce formatting variance** introduced by CTI sources (markdown, headers, bullet lists, captions, HTML/CSS fragments).
- **Preserve semantics** by avoiding paraphrasing or enrichment (normalization focuses on structure, not meaning).
- **Improve parseability** by converting layout cues into consistent sentence-like forms.

### 2.2 Implemented Normalizations and Filters

A-1 consists of two layers:
1) **Filtering**: remove lines that are overwhelmingly structural and unlikely to carry event semantics.
2) **Text normalization + rewriting**: standardize and rewrite common CTI formatting into sentence-like text.
  
#### (A) Filtering: drop non-semantic structural artifacts
Before normalization, records are filtered out if `raw_text` matches any of the following:  

- **Structural noise** (`is_structural_noise`)
  - empty/whitespace-only or no alphabetic content
  - HTML/XML artifacts (e.g., CDATA, tags, comment markers)
  - CSS-like fragments (e.g., `.class {` or `key: value;`)
  - markdown image syntax (`![alt](...)`) or table-like rows (`| ... |`)
  - figure/table caption stubs (`Figure 1`, `Table 2`, etc.)

- **Date-only lines** (`is_date_only`)
  - standalone dates like `May 18, 2021`, `2021`, or `05/18/2021`

- **API hash mappings** (`is_api_hash_mapping`)
  - patterns like `0xABCDEF -> SomeFunctionName`

- **IoC-only artifacts / indicator stubs** (`is_ioc_artifact`)
  - standalone IoCs (especially defanged domains like `example[.]com`)
  - IoC + very short label (≤3 words) that looks like a list entry rather than a sentence

This filtering step enforces a clean separation between:  
- **text that can support event extraction**, and
- **formatting/metadata fragments** that would otherwise create false events.
  
#### (B) IoC placeholder handling (implemented)
To prevent IoCs from being incorrectly extracted as actors/objects, A-1 replaces them with stable placeholders:  

- URLs → `<URL>`
- IPv4 (including defanged `[.]`) → `<IP_ADDRESS>`
- emails → `<EMAIL>`
- file hashes (MD5/SHA1/SHA256) → `<FILE_HASH>`

Placeholders are normalized so odd variants like `<< URL >>` become `<URL>`.  

#### (C) Basic cleanup (implemented)
A-1 also standardizes common markup formatting:  

- **Markdown link stripping**: `[text](url)` → `text`
- **Bullet marker removal**: leading `*`, `+`, `-` are stripped
- **Markdown emphasis removal**: `*bold*`, `**bold**`, `***bold***` → `bold`
- whitespace cleanup is implicitly handled through stripping operations

#### (D) Structural rewriting into sentence-like forms (implemented)
A-1 rewrites several common CTI structural patterns via `rewrite_structural_elements()`:

1) **Markdown section headers → declarative sentence**
- Input: `## Initial Access`
- Output: `This section discusses Initial Access.`

2) **Numbered subsection titles → declarative sentence**
- Input: `2.1 Credential Theft`
- Output: `This subsection discusses Credential Theft.`

3) **Figure captions → declarative sentence**
- Input: `Figure 3: Attack flow overview`
- Output: `Figure 3 illustrates Attack flow overview.`

4) **“short-left - explanation” artifact lines → declarative sentence**
- Input: `Loader - responsible for staging payload`
- Output: `The Loader component is responsible for staging payload.`

5) **Definition-style bullets (subject: long explanation)**
- Input: `Persistence: achieved via registry run keys and scheduled tasks...`
- Output: `Persistence is achieved via registry run keys and scheduled tasks...`
  - This rewrite is applied only when the right-hand side is long enough to look like a real explanation.


#### (E) Colon title normalization (implemented)
Some CTI sources use colon structures as titles. `normalize_colon_titles()` handles these by collapsing “title: long sentence” patterns into the main content.  

- If the left side looks like a short title and the right side is longer, return the right side.
- Otherwise, keep the original text unchanged.

### 2.3 Why These Choices

CTI text frequently encodes meaning through layout such as headers, bullets, captions, indicator lists. A-2 event extraction performs best when its input is closer to:  
- clean, sentence-like text
- consistent punctuation and markup
- reduced presence of purely structural fragments

These A-1 steps are chosen to:
- **minimize false positives**, by filtering structural fragments and IoC-only lines.
- **reduce brittleness** by normalizing IoCs and markdown.
- **improve syntactic consistency** by rewriting headers/captions into declarative sentences.

However, there is a trade-off.  
Some rewrites introduce light templating language for headers and captions, such as "This section discusses ...", "Figure X illustrates ...".  
While this is intentional, as turning into declarative sentences improves syntactic consistency for parsing, it introduces syntheitc subjects or verbs that can be mistakenly interpreted as real events. Downstream extraction can mitigate this by tagging these sentences as meta during A-1 or filtering them during A-2.  

