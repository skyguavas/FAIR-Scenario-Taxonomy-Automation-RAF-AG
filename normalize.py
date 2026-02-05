import json
import os
import re


def load_raw_sentence_records(path, limit=None):
    """Load raw sentence records from JSONL dataset."""
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            if limit is not None and i >= limit:
                break

            row = json.loads(line)
            records.append({
                "sentence_id": row["id"],
                "raw_text": row["text"],
                "normalized_text": row["text"],
                "events": []
            })
    return records


def write_sample_results(records, output_path, limit=10):
    """Write sample results to JSON file."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    sample = records[:limit] if limit else records

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sample, f, indent=2, ensure_ascii=False)


def print_raw_samples(records, n = 5):
    for r in records[:n]:
        print(f"Sentence ID: {r['sentence_id']}")
        print(f"Raw Text: {r['raw_text']}")
        print("-" * 60)


def is_structural_noise(text: str) -> bool:
    """Detect structural artifacts that should be filtered out entirely."""
    text = text.strip()
    
    # Empty or whitespace-only
    if not text or not re.search(r"[A-Za-z]", text):
        return True
    
    # HTML/XML artifacts
    if re.search(r"<!\[CDATA\[|<!--|-->|</|/>", text):
        return True
    
    # CSS patterns
    css_patterns = [
        r"^\.[\w\-]+\s+[\w\-]+\s+\w+\s*\{?$",           # .class elem prop {
        r"^[a-zA-Z\-]+\s*:\s*[^;]+;?$",                 # property: value;
        r"^\.[\w\-]+(\s+\.[\w\-]+)+\s+\w+\s*\{?$",     # compound selectors
    ]
    if any(re.match(p, text) for p in css_patterns):
        return True
    
    # Markdown artifacts
    if re.search(r"!\[.*?\]\(.*?\)", text):  # Image embeds
        return True
    if text.startswith("|") and "|" in text:  # Tables
        return True
    
    # Figure/Table captions
    if re.match(r"^(Figure|Table)\s+\d+", text, re.IGNORECASE):
        return True
    
    return False


def is_date_only(text: str) -> bool:
    """Detect standalone date lines."""
    text = text.strip()
    date_patterns = [                         # Pattern such as
        r"^[A-Za-z]+\s+\d{1,2},\s+\d{4}$",    # May 18, 2021
        r"^\d{4}$",                            # 2021
        r"^\d{1,2}/\d{1,2}/\d{2,4}$"          # 05/18/2021
    ]
    return any(re.match(p, text) for p in date_patterns)


def apply_filters(records):
    """Apply noise and date filters to remove unwanted records."""
    filtered = []
    for r in records:
        if is_structural_noise(r["raw_text"]) or is_date_only(r["raw_text"]):
            continue
        filtered.append(r)
    return filtered


def remove_markdown_links(text: str) -> str:
    """Convert [link text](url) to link text."""
    return re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)


def strip_markdown_emphasis(text: str) -> str:
    """Remove markdown emphasis markers (*bold*, **bold**)."""
    return re.sub(r"^\*+|\*+$", "", text).strip()


def strip_inline_markdown_emphasis(text: str) -> str:
    """
    Remove inline markdown emphasis like *word*, **word**, ***word***
    without touching surrounding text.
    """
    return re.sub(r"\*{1,3}([^*\n]+)\*{1,3}", r"\1", text)


def strip_bullet_markers(text: str) -> str:
    """Remove bullet point markers (*, +, -)."""
    return re.sub(r"^[\*\+\-]\s*", "", text)


def replace_iocs_with_placeholders(text: str) -> str:
    """Replace indicators of compromise with standardized placeholders."""
    # URLs (http/https)
    text = re.sub(
        r"https?://[^\s\)]+", 
        "<URL>", 
        text, 
        flags=re.IGNORECASE)
    
    # IPv4 addresses
    text = re.sub(
        r"\b(?:\d{1,3}(?:\.|\[\.\])){3}\d{1,3}\b",
        lambda m: "<IP_ADDRESS>"
        if any(len(octet) >= 2 for octet in re.split(r"\.|\[\.\]", m.group()))
        else m.group(),
        text
    )
    
    # Email addresses
    text = re.sub(
        r"\b[\w\.-]+@[\w\.-]+\.\w+\b", 
        "<EMAIL>", 
        text)
    
    # File hashes (MD5: 32, SHA1: 40, SHA256: 64)
    text = re.sub(
        r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b",
        "<FILE_HASH>",
        text
    )
    
    return text


def normalize_ioc_placeholders(text: str) -> str:
    """Normalize malformed IoC placeholders to canonical form."""
    ioc_types = ["URL", "IP_ADDRESS", "EMAIL", "FILE_HASH"]
    for ioc_type in ioc_types:
        # Collapse any malformed angle brackets: <<URL>>, < URL >, etc.
        text = re.sub(
            rf"<+\s*{ioc_type}\s*>+", 
            f"<{ioc_type}>", 
            text)
    return text


def normalize_section_header(text: str) -> str | None:
    """
    Convert section-style headers into prose.
    Handles:
      - Markdown headers: ## Security
      - Numbered subsections: 1.2.1.1 Socat
    """

    text = text.strip()

    # Case 1: Markdown headers (##, ###, etc.)
    if re.match(r"^#{1,6}\s+", text):
        clean = re.sub(r"^#{1,6}\s*", "", text)
        clean = re.sub(r"^\d+(\.\d+)*\s*", "", clean)
        clean = strip_markdown_emphasis(clean)
        return f"This section discusses {clean}."

    # Case 2: Numbered subsection headers (e.g., 1.2.1.1 Socat)
    m = re.match(r"^(\d+(?:\.\d+)+)\s+(.+)$", text)
    if m:
        _, title = m.groups()
        title = strip_markdown_emphasis(title)
        return f"This subsection discusses {title}."

    return None



def normalize_figure_caption(text: str) -> str | None:
    """Convert figure captions to prose: 'Figure 1: Attack flow' -> 'Figure 1 illustrates attack flow.'"""
    # Only match if "Figure N:" appears anywhere (not just figure-only lines)
    match = re.match(r".*Figure\s+(\d+)\s*[:–-]\s*(.+)", text, re.IGNORECASE)
    if not match:
        return None
    
    fig_num, description = match.groups()
    description = strip_markdown_emphasis(description)
    return f"Figure {fig_num} illustrates {description}."


def normalize_bullet_artifact(text: str) -> str | None:
    """
    Convert bullet-style artifact descriptions into prose.
    """

    if " - " not in text:
        return None

    left, right = text.split(" - ", 1)

    if len(left.split()) > 5:
        return None
    if len(right.split()) < 4:
        return None

    return f"The {left.strip()} component is {right.strip().rstrip('.') }."


def rewrite_structural_elements(text: str) -> str:
    """Apply structural rewriting rules in priority order."""
    for rewrite_fn in [
        normalize_section_header,
        normalize_figure_caption,
        normalize_bullet_artifact
    ]:
        rewritten = rewrite_fn(text)
        if rewritten:
            return rewritten
    
    return text


def normalize_colon_titles(text: str) -> str:
    """Remove title prefixes from 'Title: actual content' patterns."""
    if ":" not in text:
        return text
    
    left, right = text.split(":", 1)
    left = left.strip()
    right = right.strip()
    
    # Apply heuristics to determine if this is a title pattern
    is_title_pattern = (
        len(left.split()) <= 6 and              # Left side is short (title-like)
        not re.search(r"[.!?]$", left) and      # Left side doesn't end with punctuation
        len(right.split()) > len(left.split())  # Right side is meaningfully longer
    )
    
    return right if is_title_pattern else text


def apply_text_normalization(records):
    """Apply all text normalization transformations."""
    for record in records:
        text = record["normalized_text"]
        
        # 1. Basic cleanup
        text = remove_markdown_links(text)
        text = strip_bullet_markers(text)
        text = strip_inline_markdown_emphasis(text)
        text = strip_markdown_emphasis(text)
        
        # 2. Structural rewriting
        text = rewrite_structural_elements(text)
        
        # 3. IoC placeholding
        text = replace_iocs_with_placeholders(text)
        text = normalize_ioc_placeholders(text)
        
        # 4. Title normalization
        text = normalize_colon_titles(text)
        
        record["normalized_text"] = text
    
    return records


if __name__ == "__main__":
    records = load_raw_sentence_records(
        "data/raw/annoctr_train.json",
        limit=None
    )
    print(f"Loaded records: {len(records)}")
    
    # Apply filters
    records = apply_filters(records)
    print(f"After filtering: {len(records)}")
    
    # Apply normalization
    records = apply_text_normalization(records)
    print(f"After normalization: {len(records)}")
    
    # Write results
    write_sample_results(
        records,
        output_path="outputs/sample_results.json",
        limit=None
    )
    print("Results written to outputs/sample_results.json")