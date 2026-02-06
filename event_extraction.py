# """
# A-2: Event Extraction
# Standalone script that processes A-1 normalized output.

# Input:  outputs/A1_results.json (from A-1 normalization)
# Output: outputs/A2_results.json (extracted events)
# """

# import json
# import os
# import re
# from dataclasses import asdict, dataclass
# from typing import Dict, List, Optional

# import spacy

# nlp = spacy.load("en_core_web_sm")

# ################################################################################
# # EVENT STRUCTURE
# ################################################################################


# EVENT_VERBS = {
#     "execute", "run", "download", "drop", "install",
#     "communicate", "connect", "send", "receive",
#     "exfiltrate", "exploit", "abuse", "redirect"
# }

# def is_candidate_sentence(text: str) -> bool:
#     text = text.lower()
#     return any(v in text for v in EVENT_VERBS)


# @dataclass
# class Event:
#     """
#     Structured event following FAIR scenario taxonomy.
    
#     FAIR Mapping:
#     - actor → Threat (who is performing the attack)
#     - action → Method (how the attack is carried out)
#     - object → Asset (what is being targeted)
#     """
#     actor: str
#     action: str
#     object: str
#     source_sentence_id: Optional[str] = None
#     extraction_method: str = "rule_based"
    
#     def to_dict(self):
#         """Convert to dictionary for JSON serialization."""
#         return asdict(self)


# ################################################################################
# # ENHANCED EVENT EXTRACTOR
# ################################################################################

# class EnhancedCTIExtractor:
#     """
#     Enhanced extractor tuned for phishing/social engineering CTI reports.
    
#     Handles:
#     - Passive voice ("TLDs were abused by threat actor")
#     - Infrastructure creation ("site created by actor")
#     - Spoofing/impersonation patterns
#     - User redirection flows
#     """
    
#     def __init__(self):
#         # Common threat actors
#         self.threat_actors = {
#             'apt28', 'apt29', 'apt32', 'apt41', 'lazarus', 'kimsuky',
#             'turla', 'fancy bear', 'cozy bear', 'sandworm',
#             'threat actor', 'attacker', 'adversary', 'malicious actor',
#             'hacker', 'cybercriminal'
#         }
        
#         # Action verbs (expanded for phishing campaigns)
#         self.action_verbs = {
#             'accessed', 'compromised', 'breached', 'infiltrated', 'gained access',
#             'deployed', 'installed', 'executed', 'launched', 'dropped',
#             'connected', 'communicated', 'sent', 'transmitted', 'exfiltrated',
#             'encrypted', 'modified', 'deleted', 'stole', 'harvested',
#             'exploited', 'leveraged', 'utilized', 'abused',
#             'phished', 'tricked', 'deceived', 'targeted',
#             'spoofed', 'created', 'designed', 'redirected', 'displayed',
#             'clicked', 'observed', 'attempted', 'mimicked', 'impersonated'
#         }
        
#         # Assets (expanded for phishing)
#         self.assets = {
#             'credentials', 'password', 'data', 'database', 'file', 'document',
#             'system', 'server', 'endpoint', 'network', 'application',
#             'email', 'account', 'user', 'administrator', 'victim',
#             'tld', 'domain', 'portal', 'landing page', 'site', 'webpage',
#             'voicemail', 'brand'
#         }
        
    
#     def extract(self, text: str, sentence_id: str = None) -> List[Event]:
#         if not is_candidate_sentence(text):
#             return []

#         events = []

#         events.extend(self._extract_rule_event(text, sentence_id))

#         events.extend(self._extract_dependency_event(text, sentence_id))

#         return events

    
#     def _extract_actor(self, text_lower: str) -> Optional[str]:
#         """Extract threat actor from text."""
#         for actor in self.threat_actors:
#             if actor in text_lower:
#                 return actor
        
#         if 'malware' in text_lower:
#             return 'malware'
#         if 'ransomware' in text_lower:
#             return 'ransomware_operator'
#         if 'trojan' in text_lower or 'backdoor' in text_lower:
#             return 'malware_operator'
        
#         return 'threat_actor'
    

#     def _extract_rule_event(self, text: str, sentence_id: str) -> List[Event]:
#         text_lower = text.lower()
#         events = []

#         actor = self._extract_actor(text_lower)
#         action = self._extract_action(text_lower)
#         obj = self._extract_object(text_lower)

#         if actor and action:
#             events.append(Event(
#                 actor=actor,
#                 action=action,
#                 object=obj,
#                 source_sentence_id=sentence_id,
#                 extraction_method="rule_based"
#             ))

#         return events


#     def _extract_action(self, text_lower: str) -> Optional[str]:
#         """Extract action verb from text."""
#         for action in self.action_verbs:
#             if action in text_lower:
#                 return action.replace(' ', '_')
#         return None
    
#     def _extract_object(self, text_lower: str) -> Optional[str]:
#         """Extract target asset from text."""
#         for asset in self.assets:
#             if asset in text_lower:
#                 return asset
        
#         if '<EMAIL>' in text_lower:
#             return 'email_account'
#         if '<IP_ADDRESS>' in text_lower or '<URL>' in text_lower:
#             return 'network_resource'
#         if '<FILE_HASH>' in text_lower:
#             return 'malicious_file'
        
#         return 'target_system'
    
    
#     def _extract_dependency_event(self, text: str, sentence_id: str) -> List[Event]:
#         doc = nlp(text)
#         events = []

#         for token in doc:
#             if token.dep_ == "ROOT" and token.pos_ == "VERB":
#                 actor = None
#                 obj = None

#                 # SUBJECT → actor
#                 for child in token.children:
#                     if child.dep_ in ("nsubj", "nsubjpass"):
#                         actor = child.text.lower()

#                 # OBJECT → asset
#                 for child in token.children:
#                     if child.dep_ == "dobj":
#                         obj = child.text.lower()

#                     if child.dep_ == "prep":
#                         for sub in child.children:
#                             if sub.dep_ == "pobj":
#                                 obj = sub.text.lower()

#                 if actor:
#                     events.append(Event(
#                         actor=self._normalize_actor(actor),
#                         action=token.lemma_,
#                         object=self._normalize_object(obj),
#                         source_sentence_id=sentence_id,
#                         extraction_method="dependency_parse"
#                     ))

#         return events


#     def _extract_malware_events(self, text: str, text_lower: str, sentence_id: str) -> List[Event]:
#         """Extract malware-specific events."""
#         events = []
        
#         if 'malware' in text_lower or 'ransomware' in text_lower or 'trojan' in text_lower:
#             action = self._extract_action(text_lower)
#             obj = self._extract_object(text_lower)
            
#             if action and obj:
#                 events.append(Event(
#                     actor='malware',
#                     action=action,
#                     object=obj,
#                     source_sentence_id=sentence_id,
#                     extraction_method="malware_pattern"
#                 ))
        
#         return events
    
#     def _extract_vulnerability_events(self, text: str, text_lower: str, sentence_id: str) -> List[Event]:
#         """Extract vulnerability exploitation events."""
#         events = []
        
#         cve_match = re.search(r'cve-\d{4}-\d{4,}', text_lower)
#         if cve_match and ('exploit' in text_lower or 'leveraged' in text_lower):
#             events.append(Event(
#                 actor=self._extract_actor(text_lower) or 'threat_actor',
#                 action='exploited_vulnerability',
#                 object='vulnerable_service',
#                 source_sentence_id=sentence_id,
#                 extraction_method="vulnerability_pattern"
#             ))
        
#         return events
    
#     def _extract_ioc_events(self, text: str, text_lower: str, sentence_id: str) -> List[Event]:
#         """Extract IoC-related events."""
#         events = []
        
#         if '<URL>' in text or '<IP_ADDRESS>' in text:
#             if any(word in text_lower for word in ['connected', 'communicated', 'contacted']):
#                 events.append(Event(
#                     actor=self._extract_actor(text_lower) or 'malware',
#                     action='established_c2_connection',
#                     object='remote_server',
#                     source_sentence_id=sentence_id,
#                     extraction_method="ioc_pattern"
#                 ))
        
#         return events
    
#     def _normalize_actor(self, actor: str) -> str:
#         if actor in ("it", "this", "that"):
#             return "malware"
#         if "malware" in actor:
#             return "malware"
#         if "attacker" in actor:
#             return "threat_actor"
#         return actor


#     def _normalize_object(self, obj: Optional[str]) -> str:
#         if not obj:
#             return "unknown"
#         if "<IP_ADDRESS>" in obj or "<URL>" in obj:
#             return "remote_server"
#         if "<FILE_HASH>" in obj:
#             return "malicious_file"
#         return obj



# ################################################################################
# # MAIN EXTRACTION FUNCTION
# ################################################################################

# def extract_all_events(records: List[Dict]) -> List[Dict]:
#     """
#     Extract events from all A-1 normalized records and remove duplicates.
#     """
#     extractor = EnhancedCTIExtractor()
#     all_events = []
#     seen = set()  # deduplication key store

#     for record in records:
#         sentence_id = record.get("sentence_id", "unknown")
#         normalized_text = record.get("normalized_text", "").strip()

#         if not normalized_text:
#             continue

#         events = extractor.extract(normalized_text, sentence_id)

#         for event in events:
#             key = (
#                 event.actor,
#                 event.action,
#                 event.object,
#                 event.source_sentence_id
#             )

#             if key in seen:
#                 continue

#             seen.add(key)
#             all_events.append(event.to_dict())

#     return all_events



# ################################################################################
# # I/O FUNCTIONS
# ################################################################################

# def load_a1_results(path):
#     """Load A-1 normalized output"""
#     with open(path, "r", encoding="utf-8") as f:
#         return json.load(f)


# def write_a2_results(events, output_path):
#     """Write A-2 extracted events"""
#     os.makedirs(os.path.dirname(output_path), exist_ok=True)
#     with open(output_path, "w", encoding="utf-8") as f:
#         json.dump(events, f, indent=2, ensure_ascii=False)



# ################################################################################
# # MAIN (A-2 ONLY)
# ################################################################################

# if __name__ == "__main__":
#     # Load A-1 results
#     print("Loading A-1 normalized results...")
#     records = load_a1_results("outputs/A1_results.json")
#     print(f"  Loaded {len(records)} records")
    
#     # Extract events
#     print("\nExtracting events from normalized text...")
#     events = extract_all_events(records)
#     print(f"  Extracted {len(events)} events")
    
#     # Write results
#     print("\nWriting results...")
#     write_a2_results(events, "outputs/A2_results.json")
#     print(f"  ✓ Saved events to: outputs/A2_results.json")
    
#     print("\n✓ A-2 Event Extraction Complete!")


"""
A-2: Event Extraction
Hybrid rule-based + dependency parsing approach

Input:  outputs/A1_results.json (from A-1 normalization)
Output: outputs/A2_results.json (extracted events)
"""

import json
import os
import re
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional

import spacy

# Load spaCy model
nlp = spacy.load("en_core_web_sm")


################################################################################
# EVENT STRUCTURE
################################################################################

EVENT_VERBS = {
    "execute", "run", "download", "drop", "install",
    "communicate", "connect", "send", "receive",
    "exfiltrate", "exploit", "abuse", "redirect",
    "access", "compromise", "deploy", "encrypt", "steal"
}


def is_candidate_sentence(text: str) -> bool:
    """Filter sentences likely to contain events (performance optimization)."""
    text_lower = text.lower()
    return any(v in text_lower for v in EVENT_VERBS)


@dataclass
class Event:
    """
    Structured event following FAIR scenario taxonomy.
    
    FAIR Mapping:
    - actor → Threat (who is performing the attack)
    - action → Method (how the attack is carried out)
    - object → Asset (what is being targeted)
    - effect → Effect (what security impact occurs)
    """
    actor: str
    action: str
    object: str
    effect: Optional[str] = None
    source_sentence_id: Optional[str] = None
    confidence: float = 0.0
    extraction_method: str = "rule_based"
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


################################################################################
# HYBRID EVENT EXTRACTOR
################################################################################

class HybridCTIExtractor:
    """
    Hybrid extractor combining rule-based patterns and NLP dependency parsing.
    
    Approach:
    1. Candidate filtering (fast gate)
    2. Rule-based extraction (precision)
    3. Dependency parsing extraction (coverage)
    4. Deduplication (keep best)
    """
    
    def __init__(self):
        # Common threat actors
        self.threat_actors = {
            'apt28', 'apt29', 'apt32', 'apt41', 'lazarus', 'kimsuky',
            'turla', 'fancy bear', 'cozy bear', 'sandworm',
            'threat actor', 'attacker', 'adversary', 'malicious actor',
            'hacker', 'cybercriminal'
        }
        
        # Action verbs
        self.action_verbs = {
            'accessed', 'compromised', 'breached', 'infiltrated', 'gained access',
            'deployed', 'installed', 'executed', 'launched', 'dropped',
            'connected', 'communicated', 'sent', 'transmitted', 'exfiltrated',
            'encrypted', 'modified', 'deleted', 'stole', 'harvested',
            'exploited', 'leveraged', 'utilized', 'abused',
            'phished', 'tricked', 'deceived', 'targeted',
            'spoofed', 'created', 'designed', 'redirected', 'displayed',
            'clicked', 'observed', 'attempted', 'mimicked', 'impersonated'
        }
        
        # Assets
        self.assets = {
            'credentials', 'password', 'data', 'database', 'file', 'document',
            'system', 'server', 'endpoint', 'network', 'application',
            'email', 'account', 'user', 'administrator', 'victim',
            'tld', 'domain', 'portal', 'landing page', 'site', 'webpage',
            'voicemail', 'brand'
        }
    
    def extract(self, text: str, sentence_id: str = None) -> List[Event]:
        """
        Extract events using hybrid approach.
        
        Returns:
            List of Event objects (duplicates removed)
        """
        # Gate: Only process candidate sentences
        if not is_candidate_sentence(text):
            return []
        
        events = []
        
        # Approach 1: Rule-based extraction
        events.extend(self._extract_rule_based(text, sentence_id))
        
        # Approach 2: Dependency parsing extraction
        events.extend(self._extract_dependency_based(text, sentence_id))
        
        # Approach 3: Pattern-specific extraction
        events.extend(self._extract_malware_events(text, text.lower(), sentence_id))
        events.extend(self._extract_vulnerability_events(text, text.lower(), sentence_id))
        events.extend(self._extract_ioc_events(text, text.lower(), sentence_id))
        
        return events
    
    # -------------------------------------------------------------------------
    # Rule-Based Extraction
    # -------------------------------------------------------------------------
    
    def _extract_rule_based(self, text: str, sentence_id: str) -> List[Event]:
        """Extract events using pattern matching rules."""
        text_lower = text.lower()
        events = []
        
        # Pattern 1: Passive voice ("X was/were [action] by [actor]")
        passive_pattern = r'(\w+(?:\s+\w+)?)\s+(?:was|were)\s+(\w+)\s+by\s+(?:the\s+)?(\w+(?:\s+\w+)?)'
        passive_match = re.search(passive_pattern, text_lower)
        if passive_match:
            obj, action, actor = passive_match.groups()
            if action in self.action_verbs:
                events.append(Event(
                    actor=actor.strip(),
                    action=action.strip(),
                    object=obj.strip(),
                    effect=self._infer_effect(action),
                    source_sentence_id=sentence_id,
                    confidence=0.75,
                    extraction_method="passive_voice_pattern"
                ))
        
        # Pattern 2: Active voice (basic keyword matching)
        actor = self._extract_actor(text_lower)
        action = self._extract_action(text_lower)
        obj = self._extract_object(text_lower)
        
        if actor and action and obj:
            events.append(Event(
                actor=actor,
                action=action,
                object=obj,
                effect=self._infer_effect(action),
                source_sentence_id=sentence_id,
                confidence=0.70,
                extraction_method="rule_based"
            ))
        
        return events
    
    def _extract_actor(self, text_lower: str) -> Optional[str]:
        """Extract threat actor from text."""
        for actor in self.threat_actors:
            if actor in text_lower:
                return actor
        
        if 'malware' in text_lower:
            return 'malware'
        if 'ransomware' in text_lower:
            return 'ransomware_operator'
        if 'trojan' in text_lower or 'backdoor' in text_lower:
            return 'malware_operator'
        
        return 'threat_actor'
    
    def _extract_action(self, text_lower: str) -> Optional[str]:
        """Extract action verb from text."""
        for action in self.action_verbs:
            if action in text_lower:
                return action.replace(' ', '_')
        return None
    
    def _extract_object(self, text_lower: str) -> Optional[str]:
        """Extract target asset from text."""
        for asset in self.assets:
            if asset in text_lower:
                return asset
        
        if '<EMAIL>' in text_lower:
            return 'email_account'
        if '<IP_ADDRESS>' in text_lower or '<URL>' in text_lower:
            return 'network_resource'
        if '<FILE_HASH>' in text_lower:
            return 'malicious_file'
        
        return 'target_system'
    
    def _infer_effect(self, action: Optional[str]) -> Optional[str]:
        """Infer security effect (FAIR Effect) from action."""
        if not action:
            return None
        
        effects = {
            'confidentiality_breach': ['accessed', 'exfiltrated', 'stole', 'harvested'],
            'integrity_violation': ['modified', 'deleted', 'corrupted'],
            'availability_loss': ['encrypted', 'disrupted', 'disabled'],
            'initial_access': ['compromised', 'breached', 'infiltrated', 'exploited'],
            'persistence': ['installed', 'deployed', 'dropped'],
            'command_and_control': ['connected', 'communicated', 'contacted'],
            'credential_theft': ['phished', 'harvested', 'stole'],
            'social_engineering': ['spoofed', 'impersonated', 'mimicked', 'tricked', 'redirected']
        }
        
        for effect, verbs in effects.items():
            if any(v in action for v in verbs):
                return effect
        
        return 'security_impact'
    
    # -------------------------------------------------------------------------
    # Dependency Parsing Extraction
    # -------------------------------------------------------------------------
    
    def _extract_dependency_based(self, text: str, sentence_id: str) -> List[Event]:
        """Extract events using spaCy dependency parsing."""
        doc = nlp(text)
        events = []
        
        for token in doc:
            # Find ROOT verb
            if token.dep_ == "ROOT" and token.pos_ == "VERB" and token.lemma_ in self.action_verbs:
                actor = None
                obj = None
                
                # Find SUBJECT (actor)
                for child in token.children:
                    if child.dep_ in ("nsubj", "nsubjpass"):
                        actor = child.text.lower()
                
                # Find OBJECT (asset)
                for child in token.children:
                    if child.dep_ == "dobj":
                        obj = child.text.lower()
                    
                    # Prepositional object
                    if child.dep_ == "prep":
                        for sub in child.children:
                            if sub.dep_ == "pobj":
                                obj = sub.text.lower()
                
                if actor:
                    events.append(Event(
                        actor=self._normalize_actor(actor),
                        action=token.lemma_,
                        object=self._normalize_object(obj),
                        effect=self._infer_effect(token.lemma_),
                        source_sentence_id=sentence_id,
                        confidence=0.65,
                        extraction_method="dependency_parse"
                    ))
        
        return events
    
    def _normalize_actor(self, actor: str) -> str:
        """Normalize pronouns and common references."""
        if actor in ("it", "this", "that"):
            return "malware"
        if "malware" in actor:
            return "malware"
        if "attacker" in actor:
            return "threat_actor"
        return actor
    
    def _normalize_object(self, obj: Optional[str]) -> str:
        """Normalize object references."""
        if not obj:
            return "unknown"
        if "<IP_ADDRESS>" in obj or "<URL>" in obj:
            return "remote_server"
        if "<FILE_HASH>" in obj:
            return "malicious_file"
        return obj
    
    # -------------------------------------------------------------------------
    # Pattern-Specific Extraction
    # -------------------------------------------------------------------------
    
    def _extract_malware_events(self, text: str, text_lower: str, sentence_id: str) -> List[Event]:
        """Extract malware-specific events."""
        events = []
        
        if 'malware' in text_lower or 'ransomware' in text_lower or 'trojan' in text_lower:
            action = self._extract_action(text_lower)
            obj = self._extract_object(text_lower)
            
            if action and obj:
                events.append(Event(
                    actor='malware',
                    action=action,
                    object=obj,
                    effect=self._infer_effect(action),
                    source_sentence_id=sentence_id,
                    confidence=0.75,
                    extraction_method="malware_pattern"
                ))
        
        return events
    
    def _extract_vulnerability_events(self, text: str, text_lower: str, sentence_id: str) -> List[Event]:
        """Extract CVE exploitation events."""
        events = []
        
        cve_match = re.search(r'cve-\d{4}-\d{4,}', text_lower)
        if cve_match and ('exploit' in text_lower or 'leveraged' in text_lower):
            events.append(Event(
                actor=self._extract_actor(text_lower) or 'threat_actor',
                action='exploited_vulnerability',
                object='vulnerable_service',
                effect='initial_access',
                source_sentence_id=sentence_id,
                confidence=0.85,
                extraction_method="vulnerability_pattern"
            ))
        
        return events
    
    def _extract_ioc_events(self, text: str, text_lower: str, sentence_id: str) -> List[Event]:
        """Extract IoC-based C2 events."""
        events = []
        
        if '<URL>' in text or '<IP_ADDRESS>' in text:
            if any(word in text_lower for word in ['connected', 'communicated', 'contacted']):
                events.append(Event(
                    actor=self._extract_actor(text_lower) or 'malware',
                    action='established_c2_connection',
                    object='remote_server',
                    effect='command_and_control',
                    source_sentence_id=sentence_id,
                    confidence=0.75,
                    extraction_method="ioc_pattern"
                ))
        
        return events


################################################################################
# MAIN EXTRACTION FUNCTION
################################################################################

def extract_all_events(records: List[Dict]) -> List[Dict]:
    """
    Extract events from all A-1 normalized records.
    
    Uses hybrid extraction and deduplicates results.
    
    Args:
        records: List of A-1 normalized records
        
    Returns:
        List of event dictionaries
    """
    extractor = HybridCTIExtractor()
    all_events = []
    seen = set()  # Deduplication
    
    for record in records:
        sentence_id = record.get("sentence_id", "unknown")
        normalized_text = record.get("normalized_text", "").strip()
        
        if not normalized_text:
            continue
        
        # Extract events using hybrid approach
        events = extractor.extract(normalized_text, sentence_id)
        
        # Deduplicate (keep first occurrence, which tends to have higher confidence)
        for event in events:
            key = (
                event.actor,
                event.action,
                event.object,
                event.source_sentence_id
            )
            
            if key not in seen:
                seen.add(key)
                all_events.append(event.to_dict())
    
    return all_events


################################################################################
# STATISTICS
################################################################################

def generate_statistics(events: List[Dict]) -> Dict:
    """Generate statistics about extracted events."""
    if not events:
        return {
            "total_events": 0,
            "unique_sentences": 0,
            "avg_confidence": 0.0,
            "extraction_methods": {},
            "effect_distribution": {},
            "actor_distribution": {}
        }
    
    unique_sentences = len(set(e.get('source_sentence_id') for e in events))
    
    confidences = [e.get('confidence', 0.0) for e in events]
    avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0
    
    # Count by method
    methods = {}
    for event in events:
        method = event.get('extraction_method', 'unknown')
        methods[method] = methods.get(method, 0) + 1
    
    # Count by effect
    effects = {}
    for event in events:
        effect = event.get('effect', 'unknown')
        effects[effect] = effects.get(effect, 0) + 1
    
    # Count by actor
    actors = {}
    for event in events:
        actor = event.get('actor', 'unknown')
        actors[actor] = actors.get(actor, 0) + 1
    
    return {
        "total_events": len(events),
        "unique_sentences": unique_sentences,
        "avg_confidence": round(avg_confidence, 3),
        "extraction_methods": methods,
        "effect_distribution": effects,
        "actor_distribution": actors
    }


################################################################################
# I/O FUNCTIONS
################################################################################

def load_a1_results(path):
    """Load A-1 normalized output (JSON format)."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_a2_results(events, output_path):
    """Write A-2 extracted events to JSON."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2, ensure_ascii=False)


################################################################################
# MAIN
################################################################################

if __name__ == "__main__":
    print("=" * 80)
    print("A-2: EVENT EXTRACTION (Hybrid Approach)")
    print("=" * 80)
    print()
    
    # Load A-1 results
    print("Loading A-1 normalized results...")
    records = load_a1_results("outputs/A1_results.json")
    print(f"  ✓ Loaded {len(records)} records")
    
    # Extract events
    print("\nExtracting events (rule-based + dependency parsing)...")
    events = extract_all_events(records)
    print(f"  ✓ Extracted {len(events)} events")
    
    # Generate statistics
    stats = generate_statistics(events)
    print(f"\nStatistics:")
    print(f"  Unique sentences with events: {stats['unique_sentences']}")
    print(f"  Average confidence: {stats['avg_confidence']:.2f}")
    print(f"  Extraction rate: {stats['unique_sentences']}/{len(records)} ({stats['unique_sentences']/len(records)*100:.1f}%)")
    
    print(f"\nExtraction methods:")
    for method, count in sorted(stats['extraction_methods'].items(), key=lambda x: x[1], reverse=True):
        print(f"  {method}: {count}")
    
    print(f"\nTop effects:")
    for effect, count in sorted(stats['effect_distribution'].items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"  {effect}: {count}")
    
    # Write results
    print("\nWriting results...")
    write_a2_results(events, "outputs/A2_results.json")
    print(f"  ✓ Saved events to: outputs/A2_results.json")
    
    # Write statistics
    stats_path = "outputs/A2_statistics.json"
    with open(stats_path, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)
    print(f"  ✓ Saved statistics to: {stats_path}")
    
    print("\n" + "=" * 80)
    print("✓ A-2 Event Extraction Complete!")
    print("=" * 80)