import json
import re

import spacy

nlp = spacy.load("en_core_web_sm")

def extract_verbs(text):
    doc = nlp(text)
    verbs = []
    for token in doc:
        if token.pos_ == "VERB":
            verbs.append(token.lemma_)
    return verbs

def extract_actor_action(text):
    doc = nlp(text)
    
    for token in doc:
        if token.pos_ == "VERB":
            action = token.lemma_
            actor = None
            
            for child in token.children:
                if child.dep_ == "nsubj":
                    actor = child.text
            
            if actor:
                return {"actor": actor, "action": action}
    
    return {"actor": None, "action": None}

def extract_full_event(text):
    doc = nlp(text)
    
    for token in doc:
        if token.pos_ == "VERB":
            action = token.lemma_
            actor = None
            obj = None
            
            for child in token.children:
                if child.dep_ == "nsubj":
                    actor = child.text
                
                if child.dep_ == "dobj":
                    obj = child.text
            
            if actor and action:  # At minimum need actor + action
                return {"actor": actor, "action": action, "object": obj}
    
    return {"actor": None, "action": None, "object": None}

KNOWN_ACTORS = [
    # exact strings
    "Lazarus", "Sandworm", "Cozy Bear", "Fancy Bear",
    "Emotet", "TrickBot", "QakBot", "IcedID",

    # regex patterns
    re.compile(r"\bAPT\d+\b"),
    re.compile(r"\bFIN\d+\b"),
    re.compile(r"\bTA\d+\b"),
    re.compile(r"\bUNC\d+\b"),
    re.compile(r"\bDEV-\d+\b"),
]

BAD_ACTORS = {"it", "this", "that", "these", "those", "we", "our", "us", "they", "their", "he", "she", "who", "which"}

def extract_event_hybrid(text):
    doc = nlp(text)
    events = []

    for token in doc:
        if token.pos_ not in {"VERB", "AUX"}:
            continue
        if token.pos_ == "AUX":
            continue

        action = token.lemma_
        actor = None
        obj = None

        for child in token.children:
            if child.dep_ == "nsubj":
                span = doc[child.left_edge.i : child.right_edge.i + 1]
                actor = span.text
            
            elif child.dep_ == "nsubjpass":
                span = doc[child.left_edge.i : child.right_edge.i + 1]
                if not obj:
                    obj = span.text
            
            elif child.dep_ in ("dobj", "obj", "pobj"):
                if child.pos_ == "NUM":
                    continue
                span = doc[child.left_edge.i : child.right_edge.i + 1]
                obj = span.text
            
            elif child.dep_ == "agent":
                for subchild in child.children:
                    if subchild.dep_ == "pobj":
                        span = doc[subchild.left_edge.i : subchild.right_edge.i + 1]
                        actor = span.text

        cve = re.search(r"CVE-\d{4}-\d+", text)
        if cve:
            obj = cve.group()

        actor_is_junk = (actor is None) or (actor.strip().lower() in BAD_ACTORS)
        if actor_is_junk:
            for known in KNOWN_ACTORS:
                if isinstance(known, re.Pattern):
                    m = known.search(text)
                    if m:
                        actor = m.group(0)
                        break
                else:
                    if known in text:
                        actor = known
                        break

        if actor and actor.strip().lower() in BAD_ACTORS:
            actor = None

        if actor is None and obj is None:
            continue

        events.append({
            "actor": actor,
            "action": action,
            "object": obj
        })

    if not events:
        return [{"actor": None, "action": None, "object": None}]

    return events


def main():
    with open("outputs/A1_results.json", "r", encoding='utf-8') as f:
        a1_data = json.load(f)
    
    events = []
    for record in a1_data:
        text = record["normalized_text"]
        sentence_id = record["sentence_id"]
        
        sentence_events = extract_event_hybrid(text)
        for event in sentence_events:
            event["source_sentence_id"] = sentence_id
            events.append(event)

    with open("outputs/A2_events.json", "w", encoding='utf-8') as f:
        json.dump(events, f, indent=2, ensure_ascii=False)
    
    print("="*60)
    print("VERIFICATION REPORT")
    print("="*60)
    print(f"A-1 input sentences: {len(a1_data)}")
    print(f"A-2 output events:   {len(events)}")

    has_actor = sum(1 for e in events if e['actor'])
    has_action = sum(1 for e in events if e['action'])
    has_object = sum(1 for e in events if e['object'])
    
    print(f"\nExtraction Quality:")
    print(f"  Events with actor:  {has_actor}/{len(events)} ({has_actor/len(events)*100:.1f}%)")
    print(f"  Events with action: {has_action}/{len(events)} ({has_action/len(events)*100:.1f}%)")
    print(f"  Events with object: {has_object}/{len(events)} ({has_object/len(events)*100:.1f}%)")
    
    print(f"\n=== First 5 Events ===")
    for i in range(min(10, len(events))):
        print(f"\n{i+1}. Sentence ID: {events[i]['source_sentence_id']}")
        print(f"   Actor:  {events[i]['actor']}")
        print(f"   Action: {events[i]['action']}")
        print(f"   Object: {events[i]['object']}")
    
    print("="*60)

if __name__ == "__main__":
    main()

