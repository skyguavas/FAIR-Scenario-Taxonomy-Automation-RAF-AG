# RAF-AG-based-CTI-decomposition

This repo implements the first step of FAIR-aligned scenario automation: transforming raw, unstructured CTI text (AnnoCTR `text`) into:  
(1) structurally normalized sentences (A-1), and  
(2) extracted event objects (A-2) that capture *who did what to what*.  

## 1. Overall Design

### 1.1 Goal
**The core question being addressed is**:  
Can unstructured CTI text be automatically transformed into a FAIR-aligned scenario structure (Threat / Asset / Method / Effect)?

### 1.2 Pipeline
**The end-to-end flow produced is as follows:**
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
A-2: Event Extraction    ──►  events: actor/action/object
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
The purpose of this module is to make raw CTI text *structurally stable* so that downstream event extraction can operate on sentences with fewer formatting artifacts and less layout-driven ambiguity.  

Concretely, A-1 aims to:  
- **Reduce formatting variance**, which is introduced by CTI sources (markdown, headers, bullet lists, captions, HTML/CSS fragments).
- **Preserve semantics**, by avoiding paraphrasing or enrichment (normalization focuses on structure, not meaning).
- **Improve parseability**, by converting layout cues into consistent sentence-like forms.

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
To prevent IoCs from being incorrectly extracted as actors/objects, this module also replaces them with stable placeholders:  

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

1) **Markdown section headers to declarative sentences**
- Input: `## Initial Access`
- Output: `This section discusses Initial Access.`

2) **Numbered subsection titles to declarative sentences**
- Input: `2.1 Credential Theft`
- Output: `This subsection discusses Credential Theft.`

3) **Figure captions to declarative sentences**
- Input: `Figure 3: Attack flow overview`
- Output: `Figure 3 illustrates Attack flow overview.`

4) **“short-left - explanation” artifact lines to declarative sentences**
- Input: `Loader - responsible for staging payload`
- Output: `The Loader component is responsible for staging payload.`

5) **Definition-style bullets (subject: long explanation)**
- Input: `Persistence: achieved via registry run keys and scheduled tasks...`
- Output: `Persistence is achieved via registry run keys and scheduled tasks...`
  - This rewrite is applied only when the right-hand side is long enough to look like a real explanation.


#### (E) Colon title normalization (implemented)
Some sources use colon structures as titles. `normalize_colon_titles()` handles these by collapsing “title: long sentence” patterns into the main content.  

- If the left side looks like a short title and the right side is longer, return the right side.
- Otherwise, keep the original text unchanged.

### 2.3 Why These Choices

CTI text frequently encodes meaning through layout such as headers, bullets, captions, indicator lists. A-2 event extraction performs best when its input is closer to:  
- clean, sentence-like text.
- consistent punctuation and markup.
- reduced presence of purely structural fragments.

These steps are chosen to:
- **minimize false positives**, by filtering structural fragments and IoC-only lines.
- **reduce brittleness** by normalizing IoCs and markdown.
- **improve syntactic consistency** by rewriting headers/captions into declarative sentences.

However, there is a trade-off.  
Some rewrites introduce light templating language for headers and captions, such as "This section discusses ...", "Figure X illustrates ...".  
While this is intentional, as turning into declarative sentences improves syntactic consistency for parsing, it introduces synthetic subjects or verbs that can be mistakenly interpreted as real events.  
Downstream extraction can mitigate this by tagging these sentences as meta during A-1 or filtering them during A-2.  

## 3. A-2: Event Extraction
### 3.1 Design Intent

A-2 converts **normalized CTI sentences (A-1 output)** into **event-level structures** that can later be mapped into FAIR-aligned scenario fields.  

Here, an “event” is defined as:  
- **actor**: who performed the action, such as a threat group, malware, attacker, etc.
- **action**: the action that occurred or the main verb
- **object**: what the action was applied to, such as the victim, system, data, CVE, credential, etc.
- **source_sentence_id**: tracks origin back to the sentence

This module aims to:  
- turn text into a consistent event schema.
- preserve source back to the sentence, for errors to be debuggable.
- handle common CTI grammar patterns, such as active voice, passive voice, “by X”.

### 3.2 Implemented Event Extraction
This implementation is **hybrid**, and comprises:
- **Dependency Parsing**, which provides grammatical roles (subject/object)
- **CTI Heuristics**, which helps to recover high-signal CTI entities when syntax is missing or noisy (CVE detection + known actor matching)

At a high level, the method does the following:
1. Parses the sentence
2. For each verb, attempts to build an event
3. Applies CTI-specific recovery rules
4. emits 0...N events

For each normalized sentence, A-2:  

### Note: What is spaCy?

spaCy is an open-source NLP library for Python that can tokenize text and assign linguistic structure, including:
- **Part-of-speech tags** (e.g., whether a token is a `VERB`, `NOUN`, `AUX`, etc.)
- **Dependency parsing**, which identifies grammatical roles and relationships such as:
  - `nsubj` (nominal subject — often the “actor”)
  - `obj/dobj` (object — often the “target”)
  - `pobj` (object of a preposition — common in CTI phrases like “into the network”)
  - `agent` (passive “by …” phrases — often contains the actor)

In this repo, spaCy is used as a **training-free baseline** to recover clause structure from normalized CTI sentences. The extractor does not rely on a labeled dataset. Instead, it uses spaCy’s syntactic output plus CTI-specific heuristics (CVE regex + known actor matching).

#### Step 1 - Finding candidate actions (verbs)
- The extractor parses the sentence with spaCy (`en_core_web_sm`)
- It iterates over tokens and uses main verbs as event anchors:
    - includes `VERB`
    - ignores `AUX` or auxiliary to avoid low-signal actions like be/have/do. These usually encode tense/modality rather than a CTI action.  

Each remaining verb token yields:
- `action = token.lemma_`

#### Step 2 - Extracting actors (who)
For the current verb token, A-2 attempts to extract an actor via dependency relations:

- **Active voice subject**
  - If a child of the verb has `dep_ == "nsubj"`, that child is treated as the actor.
  - `nsubj` denotes the actor span.  
  - The actor is expanded to a full noun phrase span, by using `left_edge:right_edge` to capture multiword actors.  
  - example: `The Lazarus Group` instead of `Group`

This span expansion matters as actors are often multiword. If we only took a single token, we would lose critical context.

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

If the actor is missing A-2 falls back to known-actor scanning (see Step 4).

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
If a CVE identifier is present anywhere in the sentence (CVE-\d{4}-\d+), and denotes a public ID for known security vulnerabilities.
The extractor sets:
  - object = <CVE-ID>
- Rationale: CVE IDs are high-signal and often the most important “object” in exploitation narratives even when grammar is incomplete.

2) **Known actor recovery**
Sometimes the parsed actor is missing (no nsubj, no agent).  
In that case, the extractor scans the raw sentence for known actors:
  - exact string actors: `Lazarus`, `Sandworm`, `Emotet`, `TrickBot`, etc.
  - regex actor IDs: `APT\d+`, `FIN\d+`, `TA\d+`, `UNC\d+`, `DEV-\d+`, etc.
If a match is found, it becomes the actor.  

- Rationale: CTI actor names/IDs often appear as proper tokens that may not always be recovered as grammatical subjects.

#### Step 5 — Emit events (possibly multiple per sentence)
**One event per verb**
The extractor may emit multiple events from the same sentence because it iterates over every verb token.  
  - This preserves partial events when actor is omitted but object exists (common in passive CTI)

**Emission rule (currently)**
An event is emitted if at least one of (actor, object) is present. This keeps partial events when CTI omits an explicit actor.  

If no events are found, return a single null event to keep outputs consistent:
  - `{"actor": null, "action": null, "object": null}`

This keeps output shape consistent for debugging and downstream evaluation.  

### 3.3 Why These Choices
- Dependency parsing as the baseline: CTI sentences usually preserve standard clause structure even when the surrounding formatting is noisy. Dependency relations like nsubj, obj, and agent give a direct, training-free way to recover the core relationship: who did what to what.  
- Training-free and explainable: This project is early-stage and does not assume labeled event data. Dependency parsing provides a deterministic, inspectable baseline: when an event is extracted, you can trace it back to specific dependency edges (e.g., nsubj → actor, obj/pobj → object). This makes failures easy to diagnose and makes rule/filter iteration straightforward compared to a black-box approach.
- Why dependency parsing works on CTI: Even when text comes from messy sources (blogs, PDFs, bullet lists), the key claims are typically written as ordinary English statements like “X exploited Y”, “X deployed Z”, or “Y was compromised by X”. Dependency parsing is designed to recover exactly these grammatical links (subject ↔ verb ↔ object / agent), so actor/action/object extraction is feasible without labeled training data.  
- Heuristics for CTI-specific tokens: Reports frequently contain high-signal identifiers (CVE IDs, APT/FIN/UNC labels, malware family names) that may not appear as clean grammatical subjects/objects. Regex and dictionaries improve recall for these cases without adding model complexity.  
- Verb-by-verb extraction for coverage: Sources commonly compress multiple actions into a single sentence. Anchoring extraction on each verb increases recall and produces more events than forcing a single event per sentence.

### 3.4 Known Limitations / Improvement Ideas

- **Meta-sentence false positives**
  **Limitation**: A-1 sometimes rewrites structural text (headers, captions) into grammatical sentences (e.g., “This section discusses …”, “Figure 3 illustrates …”). These contain normal subjects and verbs, so A-2 can mistakenly treat them as attack events (e.g., actor="This section", action="discuss").  
  
  **Improvement**: Tag A-1 outputs as `meta` vs `content` and skip `meta` in A-2, or add a small blocklist of meta.  

  **Reason:** This is a high-impact precision win with minimal recall loss because meta sentences rarely describe attacker behavior, but they are syntactically “event-like,” making them a common false-positive source.

- **No document-level co-reference**
  **Limitation**: The extractor operates sentence-by-sentence, so it does not connect references like “the actor”, “they”, or “the malware” back to an entity named earlier in the report. This leads to missing or dropped actors even when the document context makes them obvious.  
  
  **Improvement**: Adding lightweight co-reference resolution or a rolling “last known actor/malware” memory per document.  

  **Reason**: CTI reports frequently name the actor once and then rely on pronouns/aliases. Recovering these links would improve recall and consistency, which would directly help later in clustering into scenarios and mapping into FAIR Threat.  

- **Generic verb noise**
  **Limitation**: Some verbs are grammatical but not specific CTI actions (e.g., use, include, show, discuss). If extracted as action, they can produce low-signal events and reduce precision.  
  
  **Improvement**: Add a verb blocklist/allowlist (e.g., drop meta/reporting verbs such as `discuss`, `illustrate`, `describe`, `show`) and optionally normalize generic verbs.  
  
  **Reason**: Downstream scenario automation depends on action verbs that correspond to attacker behavior, such as “exploit”, “deploy”, “exfiltrate”. Filtering generic/reporting verbs yields a cleaner event stream and improves alignment with FAIR Method/Effect later on.  

- **Object typing**
  **Limitation**: The object field currently captures whatever syntactic object is available, which can mix very different things: assets (“domain controller”), data (“credentials”), vulnerabilities (“CVE-…”) and artifacts (“payload”, “DLL”). This makes direct mapping to FAIR Asset/Method/Effect ambiguous.  
  
  **Improvement**: Adding a lightweight typing layer (rules/NER) to label objects as ASSET, DATA, VULNERABILITY, or ARTIFACT.  

  **Reason**: FAIR scenario automation requires separating *what is targeted* (Asset) from *how it is done* (Method) and *what was impacted* (Effect). Typing the object early enables consistent scenario assembly, control mapping, and later quantification.

- **Junk actor suppression**
  **Limitation**: To prevent meaningless actors, the extractor should drop pronouns and demonstratives, such as it, this, they, we.

  **Reason**: Filtering them would prevent noisy “actors” that would pollute downstream scenario assembly.

## 4. Understanding of FAIR Scenario Automation
This project is scoped to the **front-end of a FAIR automation pipeline**. FAIR (Factor Analysis of Information Risk) ultimately needs a well-defined risk scenario before any quantitative modeling is possible. In practice, the biggest bottleneck is that CTI is written as narrative text, while FAIR needs structured scenario inputs. The role of this repo is to bridge that gap by producing structured events from raw CTI.

### 4.1 How A-1 and A-2 fit into a future FAIR pipeline
A realistic automation flow looks like:  
1. **Raw CTI (unstructured text)**
   - threat reports, blogs, incident writeups
   - formatting is inconsistent (headers, bullets, captions, IoCs)
  
2. **A-1: Text Normalization (structure first)**
   - converts layout-driven text into sentence-like units
   - removes non-semantic artifacts
   - ensures that A-2 sees stable, parseable inputs

3. **A-2: Event Extraction (event atoms)**
   - converts each sentence into `(actor, action, object)` events
   - preserves origin (`source_sentence_id`)
   - outputs are interpretable and can be audited

4. **Scenario Assembly (future step; not implemented)**
   - merge and cluster events into a coherent scenario:
     - group by actor / campaign / malware family
     - connect sequential actions into an attack chain
   - resolve entity consistency (aliases, pronouns, “the group”, “the malware”)

5. **FAIR Scenario Taxonomy Mapping (future step; not implemented)**
   - map the assembled scenario into FAIR fields:
     - Threat / Asset / Method / Effect

6. **Quantification (out of scope here)**
   - once the scenario is defined, FAIR modeling estimates frequency and loss magnitude
   - requires additional inputs (controls, asset values, exposure, etc.)

This repo covers steps (2) and (3). Everything after event extraction is intentionally left as future work.

### 4.2 How extracted events would map to FAIR fields
FAIR scenario definitions are typically framed as:

- **Threat** — who is performing the attack  
- **Asset** — what is being targeted  
- **Method** — how the attack is carried out  
- **Effect** — what security impact occurs  

A-2 events do not directly output FAIR fields, but they provide the raw material needed to achieve further goals.  

#### Threat (who)
- **Primary source:** `actor`
- Examples:
  - `actor = "Lazarus"` → Threat = Lazarus
  - `actor = null` → Threat may be inferred later via co-reference or clustering
- **What’s needed later:** actor normalization (aliases), confidence scoring, “threat archetype” fallback when unnamed.

#### Asset (what is targeted)
- **Primary source:** `object` (when it refers to a system/resource)
- Examples:
  - `object = "domain controller"` → Asset = identity infrastructure
  - `object = "credentials"` → this is not an asset; it is likely data (needs typing)
- **What’s needed later:** object typing so we can distinguish ASSET vs DATA vs ARTIFACT.

#### Method (how)
- **Primary source:** `action` + supporting phrases/tools (partly captured through `object` and prepositional targets)
- Examples:
  - `action = "exploit"`, `object = "CVE-2021-44228"` → Method = exploitation of known vulnerability
  - `action = "deploy"`, `object = "loader"` → Method = malware deployment
- **What’s needed later:** explicit extraction of tool/technique mentions

#### Effect (impact)
- **Primary source:** usually NOT reliably captured at the verb-object level in this baseline
- Some effects can be hinted by certain verbs/objects:
  - `action = "exfiltrate"`, `object = "data"` → confidentiality impact
  - `action = "encrypt"`, `object = "files"` → availability impact (ransomware)
- **What’s needed later:** explicit impact extraction and normalization (confidentiality/integrity/availability), plus linking to loss outcome categories.

### 4.3 Why this “event-first” approach makes sense for automation
- FAIR requires scenario components to be **explicit and repeatable**. A-2 events provide repeatable units that can be audited.
- CTI narratives often describe multi-step attacks. By extracting verb-level events, later steps can:
  - order and cluster events into an attack chain (similar to RAF-AG attack graph ideas)
  - connect those chains to FAIR scenario templates
- Keeping A-1 and A-2 modular allows future iterations to:
  - improve extraction without changing downstream mapping logic
  - add additional fields (method/tool/effect) progressively

### 4.4 Limitations and what they imply for FAIR automation

- **Actor continuity:** Without co-reference, many events will have `actor=null`, which makes Threat mapping incomplete.
- **Asset vs data ambiguity:** Without object typing, “credentials” and “domain controller” both appear as `object`, but they feed different FAIR fields.
- **Method details missing:** The baseline captures the main verb but may miss “how” phrases (tools, vectors, techniques), limiting Method fidelity.
- **Effect is not explicit:** Most CTI sentences describe actions, not quantified impact; effect extraction needs a later dedicated step.

These limitations motivate the improvement ideas listed in Section 3.4, because each directly increases the quality of mapping from events to FAIR scenario fields.  
