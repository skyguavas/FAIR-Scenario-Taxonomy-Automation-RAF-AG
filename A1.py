import json
import os
import re


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
        r"^\.[\w\-]+\s+[\w\-]+\s+\w+\s*\{?$",
        r"^[a-zA-Z\-]+\s*:\s*[^;]+;?$",
        r"^\.[\w\-]+(\s+\.[\w\-]+)+\s+\w+\s*\{?$",
    ]
    if any(re.match(p, text) for p in css_patterns):
        return True
    
    # Markdown artifacts
    if re.search(r"!\[.*?\]\(.*?\)", text):
        return True
    if text.startswith("|") and "|" in text:
        return True
    
    # Figure/Table captions
    if re.match(r"^(Figure|Table)\s+\d+", text, re.IGNORECASE):
        return True
    
    return False


def is_date_only(text: str) -> bool:
    text = text.strip()
    date_patterns = [
        r"^[A-Za-z]+\s+\d{1,2},\s+\d{4}$",    # May 18, 2021
        r"^\d{4}$",                           # 2021
        r"^\d{1,2}/\d{1,2}/\d{2,4}$"          # 05/18/2021
    ]
    return any(re.match(p, text) for p in date_patterns)


def is_api_hash_mapping(text: str) -> bool:
    return bool(
        re.fullmatch(
            r"0x[a-fA-F0-9]+\s*->\s*[A-Za-z0-9_\\]+",
            text.strip()
        )
    )


def is_ioc_artifact(text: str) -> bool:
    t = text.strip()
    t = re.sub(r"^[\*\+\-\s]+", "", t)
    ioc = r"(?:[A-Za-z0-9-]+\.)*[A-Za-z0-9-]+(?:\[\.\][A-Za-z0-9-]+)+(?:/\S+)?"

    # CASE 1: pure IoC only
    if re.fullmatch(ioc, t):
        return True

    # CASE 2: IoC + label
    m = re.fullmatch(rf"{ioc}\s+-\s+(.+)", t)
    if not m:
        return False

    label = m.group(1).strip()
    if re.search(
        r"\b(added|seen|observed|related|used|in|on|during|after|before)\b",
        label,
        re.IGNORECASE
    ):
        return False

    return len(label.split()) <= 3


def apply_filters(records):
    filtered = []
    for r in records:
        if is_structural_noise(r["raw_text"]) or is_date_only(r["raw_text"]) or is_api_hash_mapping(r["raw_text"]) or is_ioc_artifact(r["raw_text"]):
            continue
        filtered.append(r)
    return filtered


def remove_markdown_links(text: str) -> str:
    return re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)

def strip_markdown(text: str) -> str:
    text = re.sub(r"\*{1,3}([^*\n]+)\*{1,3}", r"\1", text)
    text = re.sub(r"^\*+|\*+$", "", text)
    return text.strip()

def strip_bullet_markers(text: str) -> str:
    return re.sub(r"^[\*\+\-]\s*", "", text)


def replace_iocs_with_placeholders(text: str) -> str:
    # URLs
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
    
    # File hashes
    text = re.sub(
        r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b",
        "<FILE_HASH>",
        text
    )
    
    return text


def normalize_ioc_placeholders(text: str) -> str:
    ioc_types = ["URL", "IP_ADDRESS", "EMAIL", "FILE_HASH"]
    for ioc_type in ioc_types:
        text = re.sub(
            rf"<+\s*{ioc_type}\s*>+", 
            f"<{ioc_type}>", 
            text)
    return text


def normalize_section_header(text: str) -> str | None:
    text = text.strip()

    # Case 1: Deals with markdown headers
    if re.match(r"^#{1,6}\s+", text):
        clean = re.sub(r"^#{1,6}\s*", "", text)
        clean = re.sub(r"^\d+(\.\d+)*\s*", "", clean)
        clean = strip_markdown(clean)
        return f"This section discusses {clean}."

    # Case 2: Deals with numbered subsection headers
    m = re.match(r"^(\d+(?:\.\d+)+)\s+(.+)$", text)
    if m:
        _, title = m.groups()
        title = strip_markdown(title)
        return f"This subsection discusses {title}."

    return None


def normalize_figure_caption(text: str) -> str | None:
    match = re.match(r".*Figure\s+(\d+)\s*[:–-]\s*(.+)", text, re.IGNORECASE)
    if not match:
        return None
    
    fig_num, description = match.groups()
    description = strip_markdown(description)
    return f"Figure {fig_num} illustrates {description}."


def normalize_bullet_definition(text: str) -> str | None:
    m = re.match(r"^(.{1,60})\s*:\s*(.+)", text)
    if not m:
        return None

    subject, rest = m.groups()

    if len(rest.split()) < 6:
        return None

    if re.search(r"[.!?]$", subject):
        return None

    subject = subject.strip()
    copula = "are" if subject.lower().endswith("s") else "is"

    return f"{subject} {copula} {rest}"


def normalize_bullet_artifact(text: str) -> str | None:
    if " - " not in text:
        return None

    l, r = text.split(" - ", 1)
    if len(l.split()) > 5 or len(r.split()) < 4:
        return None

    return f"The {l.strip()} component is {r.strip().rstrip('.') }."


def normalize_colon_titles(text: str) -> str:
    if ":" not in text:
        return text
    
    l, r = text.split(":", 1)
    l, r = l.strip(), r.strip()
    
    is_title_pattern = (
        len(l.split()) <= 6 and
        not re.search(r"[.!?]$", l) and
        len(r.split()) > len(l.split())
    )
    
    if is_title_pattern:
        return r
    else:
        return text


def rewrite_structural_elements(text: str) -> str:
    for rewrite in [
        normalize_bullet_definition,
        normalize_section_header,
        normalize_figure_caption,
        normalize_bullet_artifact
    ]:
        rewritten = rewrite(text)
        if rewritten:
            return rewritten
    
    return text


def apply_text_normalization(records):
    for record in records:
        text = record["normalized_text"]
        
        # 1. Initial IoC placeholding
        text = replace_iocs_with_placeholders(text)
        text = normalize_ioc_placeholders(text)

        # 2. Basic cleanup
        text = remove_markdown_links(text)
        text = strip_bullet_markers(text)
        text = strip_markdown(text)
        
        # 3. Structural rewriting
        text = rewrite_structural_elements(text)
        
        # 4. Title normalization
        text = normalize_colon_titles(text)
        record["normalized_text"] = text
    
    return records
