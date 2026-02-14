# RAF-AG-based-CTI-decomposition

This repo implements the first step of FAIR-aligned scenario automation: transforming raw, unstructured CTI text (AnnoCTR `text`) into:  
(1) structurally normalized sentences (A-1), and  
(2) extracted event objects (A-2) that capture *who did what to what (and optionally how)*.  

## 1. Overall Design

### 1.1 Goal
**Core Question**:  
Can unstructured CTI text be automatically transformed into a FAIR-aligned scenario structure (Threat / Asset / Method / Effect)?

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
    "actor": "...",
    "action": "...",
    "object": "...",
    "source_sentence_id": "..."
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
- clean, sentence-like text.
- consistent punctuation and markup.
- reduced presence of purely structural fragments.

These A-1 steps are chosen to:
- **minimize false positives**, by filtering structural fragments and IoC-only lines.
- **reduce brittleness** by normalizing IoCs and markdown.
- **improve syntactic consistency** by rewriting headers/captions into declarative sentences.

However, there is a trade-off.  
Some rewrites introduce light templating language for headers and captions, such as "This section discusses ...", "Figure X illustrates ...".  
While this is intentional, as turning into declarative sentences improves syntactic consistency for parsing, it introduces syntheitc subjects or verbs that can be mistakenly interpreted as real events. Downstream extraction can mitigate this by tagging these sentences as meta during A-1 or filtering them during A-2.  

## 3. A-2 Event Extraction (What + How + Why)
### 3.1 Design Intent

A-2 converts **normalized CTI sentences (A-1 output)** into **event-level structures** that can later be mapped into FAIR-aligned scenario fields.  

Here, an “event” is defined as:  
- **actor**: who performed the action, such as a threat group, malware, attacker, etc.
- **action**: the action that occurred or the main verb
- **object**: what the action was applied to, such as the victim, system, data, CVE, credential, etc.
- **source_sentence_id**: provenance back to the sentence

A-2 aims to:  
- turn text into a consistent event schema.
- preserve source back to the sentence, for errors to be debuggable.
- handle common CTI grammar patterns, such as active voice, passive voice, “by X”.

### 3.2 Implemented Event Extraction
This implementation is **hybrid**:
- **Dependency Parsing** provides grammatical roles (subject/object)
- **CTI Heuristics** recover high-signal CTI entities when syntax is missing or noisy (CVE detection + known actor matching)

At a high level, the method does the following:
1. Parse the sentence
2. For each verb, attempt to build an event
3. Apply CTI-specific recovery rules
4. emit 0...N events

For each normalized sentence, A-2:  
#### Step 1 - Finding candidate actions (verbs)
- The extractor parses the sentence with spaCy (`en_core_web_sm`)
- It iterates over tokens and uses main verbs as event anchors::
    - includes `VERB`
    - ignores `AUX` or auxiliary to avoid low-signal actions like be/have/do. These usually encode tense/modality rather than a CTI action.  

Each remaining verb token yields:
- `action = token.lemma_`

#### Step 2 - Extracting actors (who)
For the current verb token, A-2 attempts to extract an actor via dependency relations:

- **Active voice subject**
  - If a child of the verb has `dep_ == "nsubj"`, that child is treated as the actor.
  - `nsubj` denotes the actor span.  
  - The actor is expanded to a full noun phrase span, by using `left_edge:right_edge` to capture multiword actors  
  - example: `The Lazarus Group` instead of `Group`

This span expansion matters as CTI actors are often mutliworded. If we only took a single token, we would lose critical context.

- **Passive voice agent**
Passive constructions often place the true actor inside a “by …” phrase.  
example: `The payload was deployed by Lazarus.`  
spaCy represents this as:  
  - agent dependency (the “by”-phrase)
  - with a pobj child inside it (“Lazarus”)

So, the process:
  - detects child.dep_ == "agent"
  - then searches its children for dep_ == "pobj"
  - and uses that span as actor

If the actor is missing or junk (pronouns/demonstratives), A-2 falls back to known-actor scanning (see Step 4).

#### Step 3 — Extracting object (what was acted on)
For the same verb token, A-2 tries to extract an object. Since both direct objects and prepositional targets are crucial, extraction is ordered:  

- Preferred:
  - `dobj` / `obj` (direct object)
  - example: `Actor exfiltrated data.`
  - The noun attached to the verb via dobj/obj becomes the object.
  
- Fallback:
  - `pobj` (prepositional object)
  - example: “Actor moved laterally into the network.”
  - The noun inside a prepositional phrase (pobj) is used as object.

- Exclusion:
  - skip numeric-only objects (`pos_ == "NUM"`) to reduce junk captures

Object spans are expanded using `left_edge:right_edge` to capture full phrases.


#### Step 4 — CTI heuristics (CVE + known actor recovery)
Dependency parsing is not always sufficient for CTI due to missing subjects, unusual formatting, or indicator-heavy text. This implementation adds two CTI-specific recovery rules:

1) **CVE override**
If a CVE identifier is present anywhere in the sentence (CVE-\d{4}-\d+),
the extractor sets:
  - object = <CVE-ID>
- Rationale: CVE IDs are high-signal and often the most important “object” in exploitation narratives even when grammar is incomplete.

2) **Known actor recovery**
Sometimes the parsed actor is:
  - missing (no nsubj, no agent)
  - or junk (pronoun/demonstrative)

In that case, the extractor scans the raw sentence for known actors:
  - exact string actors: `Lazarus`, `Sandworm`, `Emotet`, `TrickBot`, etc.
  - regex actor IDs: `APT\d+`, `FIN\d+`, `TA\d+`, `UNC\d+`, `DEV-\d+`, etc.
If a match is found, it becomes the actor.  

- Rationale: CTI actor names/IDs often appear as proper tokens that may not always be recovered as grammatical subjects.

3) **Junk actor suppression**
To prevent meaningless actors, the extractor drops pronouns/demonstratives:
  - example: `it`, `this`, `they`, `we`
If the recovered actor is still junk, it is set to null.

#### Step 5 — Emit events (possibly multiple per sentence)
One event per verb
The extractor may emit multiple events from the same sentence because it iterates over every verb token.  
  - This preserves partial events when actor is omitted but object exists (common in passive CTI)

Emission rule (currently)
An event is emitted if at least one of (actor, object) is present. This keeps partial events when CTI omits an explicit actor.  

If no events are found, return a single null event to keep outputs consistent:
  - `{"actor": null, "action": null, "object": null}`

This keeps output shape consistent for debugging and downstream evaluation.  

### 3.3 Why These Choices
- - CTI text often contains enough clause structure for dependency parsing to recover **subject/object** relationships without training data.
- Dependency parsing first: It gives a transparent baseline “who/what” extraction without requiring training labels.
- Regex/dictionary heuristics are necessary because sentences include structured identifiers (CVE IDs, APT/FIN/UNC IDs, malware names) that are high-signal but not guaranteed to appear as clean subjects/objects.
- Verb-by-verb extraction improves recall because sentences frequently contain multiple actions.
- Junk-actor filtering prevents pronouns (“it/they/this”) from becoming meaningless threat actors.


### 3.4 Known Limitations / Improvement Ideas

- **Meta-sentence false positives**: rewritten A-1 sentences like “This section discusses …” can produce non-attack events unless filtered/tagged.
- **No document-level co-reference**: “the actor / they / the malware” is not linked across sentences.
- **Generic verbs**: actions like `use`, `include`, `show` may be extracted and can reduce precision without a verb blocklist.
- **Object typing**: objects mix assets, data, vulnerabilities, and artifacts (no classification yet).

Improvements:
- Tag A-1 outputs as `meta` vs `content` and skip `meta` in A-2.
- Add blocklists for meta verbs (`discuss`, `illustrate`, `describe`) and meta actors (`section`, `figure`, `table`).
- Add a confidence score based on whether actor/object were recovered via dependencies vs heuristics.