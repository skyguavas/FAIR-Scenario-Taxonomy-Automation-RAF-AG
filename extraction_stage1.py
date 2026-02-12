import spacy

nlp = spacy.load("en_core_web_sm")

def extract_verbs(text):
    doc = nlp(text)
    verbs = []
    for token in doc:
        if token.pos_ == "VERB":
            verbs.append(token.lemma_)  # lemma = base form
    return verbs

def extract_actor_action(text):
    doc = nlp(text)
    
    for token in doc:
        if token.pos_ == "VERB":
            action = token.lemma_
            actor = None
            
            # Find subject
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

import re


def extract_event_hybrid(text):
    doc = nlp(text)
    events = []

    known_actors = ["APT28", "APT29", "Lazarus", "FIN7", "Emotet", "TrickBot"]
    bad_actors = {"it", "this", "that", "malware", "trojan", "virus"}

    for token in doc:
        # Only consider actual verb predicates (skip AUX like "is/was/has")
        if token.pos_ != "VERB" or token.dep_ == "aux":
            continue

        action = token.lemma_
        actor = None
        obj = None

        # --- dependency parsing from THIS verb (fix: root -> token) ---
        for child in token.children:
            if child.dep_ in ("nsubj", "nsubjpass"):
                span = doc[child.left_edge.i : child.right_edge.i + 1]
                actor = span.text

            if child.dep_ in ("dobj", "obj", "pobj"):
                if child.pos_ == "NUM":
                    continue
                span = doc[child.left_edge.i : child.right_edge.i + 1]
                obj = span.text

        # --- rule-based improvements (PER EVENT) ---

        # CVE overrides object
        cve = re.search(r"CVE-\d{4}-\d+", text)
        if cve:
            obj = cve.group()

        # Known actor override
        for known in known_actors:
            if known in text:
                actor = known
                break

        # Filter bad actors
        if actor and actor.strip().lower() in bad_actors:
            actor = None

        # Skip empty events (optional but usually helpful)
        if actor is None and obj is None:
            continue

        events.append({
            "actor": actor,
            "action": action,
            "object": obj
        })

    # Keep your original fallback behavior if nothing found
    if not events:
        return [{"actor": None, "action": None, "object": None}]

    return events


# def extract_event_hybrid(text):
#     doc = nlp(text)
#     events = []
#     known_actors = ["APT1", "APT28", "APT29", "APT32", "APT33", "APT34", "APT41", "Lazarus", "FIN7", "FIN12", "TA505", "Sandworm",
#                     "Cozy Bear", "Fancy Bear", "Emotet", "TrickBot", "QakBot", "IcedID"]

#     bad_actors = {"it", "this", "that", "malware", "trojan", "virus"}

#     # --- find ROOT verb ---
#     root = None
#     for token in doc:
#         if token.dep_ == "ROOT" and token.pos_ == "VERB":
#             root = token
#             # break


#     # No verb → no event (design choice)
#     if root is None:
#         return [{
#             "actor": None,
#             "action": None,
#             "object": None
#         }]

#     action = root.lemma_
#     actor = None
#     obj = None

#     # --- dependency parsing from ROOT ---
#     for child in root.children:
#         if child.dep_ in ("nsubj", "nsubjpass"):
#             span = doc[child.left_edge.i : child.right_edge.i + 1]
#             actor = span.text

#         # if child.dep_ in ("dobj", "obj"):
#         #     if child.pos_ != "NUM":
#         #         obj = child.text
#         if child.dep_ in ("dobj", "obj", "pobj"):
#             if child.pos_ == "NUM":
#                 continue
#             span = doc[child.left_edge.i : child.right_edge.i + 1]
#             obj = span.text
    
#     # --- rule-based improvements ---

#     # CVE overrides object
#     cve = re.search(r"CVE-\d{4}-\d+", text)
#     if cve:
#         obj = cve.group()

#     # Known actor override
#     for known in known_actors:
#         if known in text:
#             actor = known
#             break

#     # Filter bad actors
#     if actor and actor.lower() in bad_actors:
#         actor = None

#     return [{
#         "actor": actor,
#         "action": action,
#         "object": obj
#     }]


import json


def main():
    # Load A-1 results
    with open("outputs/A1_results.json", "r", encoding='utf-8') as f:
        a1_data = json.load(f)
    
    # Extract events
    events = []
    for record in a1_data:
        text = record["normalized_text"]
        sentence_id = record["sentence_id"]
        
        sentence_events = extract_event_hybrid(text)
        for event in sentence_events:
            event["source_sentence_id"] = sentence_id
            events.append(event)

    
    # Save
    with open("outputs/A2_events.json", "w", encoding='utf-8') as f:
        json.dump(events, f, indent=2, ensure_ascii=False)
    
    # ✅ ADD VERIFICATION HERE
    print("="*60)
    print("VERIFICATION REPORT")
    print("="*60)
    print(f"A-1 input sentences: {len(a1_data)}")
    print(f"A-2 output events:   {len(events)}")
    print(f"Match: {'✓ YES' if len(a1_data) == len(events) else '✗ NO - PROBLEM!'}")
    
    # Check how many have actors/actions/objects
    has_actor = sum(1 for e in events if e['actor'])
    has_action = sum(1 for e in events if e['action'])
    has_object = sum(1 for e in events if e['object'])
    
    print(f"\nExtraction Quality:")
    print(f"  Events with actor:  {has_actor}/{len(events)} ({has_actor/len(events)*100:.1f}%)")
    print(f"  Events with action: {has_action}/{len(events)} ({has_action/len(events)*100:.1f}%)")
    print(f"  Events with object: {has_object}/{len(events)} ({has_object/len(events)*100:.1f}%)")
    
    # Show some examples
    print(f"\n=== First 5 Events ===")
    for i in range(min(10, len(events))):
        print(f"\n{i+1}. Sentence ID: {events[i]['source_sentence_id']}")
        print(f"   Actor:  {events[i]['actor']}")
        print(f"   Action: {events[i]['action']}")
        print(f"   Object: {events[i]['object']}")
    
    print("="*60)


if __name__ == "__main__":
    main()

