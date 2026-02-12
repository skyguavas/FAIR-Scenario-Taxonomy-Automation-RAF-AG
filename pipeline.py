import json
import os

from A1 import apply_filters, apply_text_normalization
from A2 import extract_event_hybrid


def load_raw_records(path, limit=None):
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            if limit is not None and i >= limit:
                break

            row = json.loads(line)
            records.append({
                "sentence_id": row["id"],
                "raw_text": row["text"],
                "normalized_text": row["text"]
            })
    return records


def write_sample_results(records, output_path, limit = 10):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    sample = records[:limit] if limit else records
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sample, f, indent = 2, ensure_ascii = False)


def pipeline(input_path, a1_out, a2_out, limit=None):
    records = load_raw_records(
        input_path,
        limit = limit
    )

    print("="*60)
    print("REPORT FOR A-1 TEXT NORMALIZATION")
    print("="*60)
    print(f"Loaded records: {len(records)}")
    
    # Filtering
    records = apply_filters(records)
    print(f"After filtering: {len(records)}")
    
    # Normalization
    records = apply_text_normalization(records)
    print(f"After normalization: {len(records)}")
    
    # Writing results
    write_sample_results(
        records,
        output_path = a1_out,
        limit = None
    )
    print("Text normalization results written to outputs/A1_results.json")

    # A-2 Event Extraction
    with open(a1_out, "r", encoding='utf-8') as f:
        a1_data = json.load(f)
    
    events = []
    for record in a1_data:
        text = record["normalized_text"]
        sentence_id = record["sentence_id"]
        
        sentence_events = extract_event_hybrid(text)
        for event in sentence_events:
            event["source_sentence_id"] = sentence_id
            events.append(event)

    with open(a2_out, "w", encoding='utf-8') as f:
        json.dump(events, f, indent=2, ensure_ascii=False)
    
    print("="*60)
    print("REPORT FOR A-2 EVENT EXTRACTION")
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
    pipeline(
        input_path = "data/raw/annoctr_train.json",
        a1_out = "outputs/A1_results.json",
        a2_out = "outputs/A2_events.json",
        limit = None
    )