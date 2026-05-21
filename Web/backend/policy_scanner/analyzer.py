import logging
from typing import List, Dict, Any
import yaml
import os

logger = logging.getLogger(__name__)

class PolicyAnalyzer:
    def __init__(self, config_path: str = None):
        if not config_path:
            config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        self.frameworks = self.config.get('frameworks', {})

    def analyze(self, text: str, target_frameworks: List[str] = None) -> Dict[str, Any]:
        text_lower = text.lower()
        findings = []
        scores = {}
        
        if not target_frameworks:
            target_frameworks = list(self.frameworks.keys())
            
        for framework in target_frameworks:
            if framework not in self.frameworks:
                continue
                
            clauses = self.frameworks[framework]
            framework_score = 0
            
            for clause in clauses:
                keywords = clause.get('keywords', [])
                found = False
                evidence = ""
                
                for keyword in keywords:
                    if keyword.lower() in text_lower:
                        found = True
                        # Simple extraction of surrounding context as evidence
                        idx = text_lower.find(keyword.lower())
                        start = max(0, idx - 50)
                        end = min(len(text), idx + len(keyword) + 50)
                        evidence = text[start:end].replace('\n', ' ').strip()
                        break
                        
                status = "present" if found else "missing"
                if found:
                    framework_score += 1
                    
                findings.append({
                    "framework": framework,
                    "clause": clause.get("clause"),
                    "status": status,
                    "evidence": f"...{evidence}..." if found else "",
                    "reason": clause.get("reason"),
                    "remediation": clause.get("remediation"),
                    "severity": clause.get("severity")
                })
                
            scores[framework] = int((framework_score / len(clauses)) * 100) if clauses else 0
            
        return {
            "findings": findings,
            "scores": scores
        }
