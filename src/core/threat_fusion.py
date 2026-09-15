"""
Threat Fusion - Combines signals from Model 1 and Model 2
"""
import logging
from typing import Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)

class ThreatFusion:
    """
    Fuses signals from known-pattern recognition and behavioral anomaly detection
    Critical case: low known-attack similarity + high behavioral deviation
    Should be described as unrecognized behavior, not confirmed zero-day
    """
    
    def fuse_threat_signals(self, threat_signal: Dict[str, Any], 
                           anomaly_signal: Dict[str, Any]) -> Dict[str, Any]:
        """
        Combine threat detector and anomaly detector results
        """
        timestamp = datetime.utcnow().isoformat()
        entity_id = threat_signal.get('entity_id')
        
        threat_score = threat_signal.get('confidence', 0)
        anomaly_score = anomaly_signal.get('anomaly_score', 0) / 100  # Normalize to 0-1
        
        # Calculate combined suspicion score
        suspicion_score = self._calculate_combined_score(threat_score, anomaly_score)
        
        # Determine threat classification
        threat_class = self._classify_threat(threat_score, anomaly_score)
        
        # Generate fusion assessment
        assessment = self._generate_assessment(threat_score, anomaly_score, threat_class)
        
        result = {
            'timestamp': timestamp,
            'entity_id': entity_id,
            'threat_signal': threat_signal,
            'anomaly_signal': anomaly_signal,
            'combined_suspicion_score': suspicion_score,
            'threat_classification': threat_class,
            'assessment': assessment,
            'recommended_action': self._recommend_action(threat_class, suspicion_score),
            'requires_human_authorization': True
        }
        
        logger.debug(f"Threat fusion for {entity_id}: {threat_class} (suspicion: {suspicion_score:.1%})")
        
        return result
    
    def _calculate_combined_score(self, threat_score: float, anomaly_score: float) -> float:
        """
        Calculate combined suspicion score
        Weights both signals but doesn't create false confidence
        """
        # If both models agree, increase confidence
        # If one model disagrees, maintain moderate confidence
        
        if threat_score > 0.7 and anomaly_score > 0.7:
            # Both models detect threat
            combined = (threat_score + anomaly_score) / 2
        elif threat_score > 0.7 or anomaly_score > 0.7:
            # One model detects threat, one doesn't
            combined = max(threat_score, anomaly_score) * 0.8
        else:
            # Combine with lower confidence
            combined = (threat_score * 0.6 + anomaly_score * 0.4)
        
        return min(combined, 1.0)
    
    def _classify_threat(self, threat_score: float, anomaly_score: float) -> str:
        """
        Classify the threat based on both signals
        Critical: Don't claim zero-day for unrecognized behavioral anomalies
        """
        if threat_score > 0.8:
            return "Known_Attack_Pattern"
        elif threat_score > 0.5 and anomaly_score > 0.7:
            return "Possible_Attack_With_Unusual_Behavior"
        elif threat_score < 0.3 and anomaly_score > 0.8:
            return "Unrecognized_Behavioral_Anomaly"
        elif threat_score < 0.3 and 0.4 < anomaly_score <= 0.8:
            return "Unusual_Behavior"
        elif threat_score > 0.5:
            return "Resembles_Known_Attack"
        else:
            return "Suspicious_Activity"
    
    def _generate_assessment(self, threat_score: float, anomaly_score: float, 
                            threat_class: str) -> str:
        """Generate human-readable threat assessment"""
        
        assessments = {
            'Known_Attack_Pattern': 
                "Traffic closely resembles known attack patterns. "
                "High confidence that this activity matches documented threats.",
            'Possible_Attack_With_Unusual_Behavior':
                "Traffic resembles known attacks AND shows unusual deviation from baseline. "
                "Possible attack with novel or evolved techniques.",
            'Unrecognized_Behavioral_Anomaly':
                "Traffic does NOT closely resemble known patterns BUT shows significant "
                "deviation from normal baseline. This is previously unseen/unusual behavior. "
                "NOT automatically confirmed as zero-day - requires investigation.",
            'Unusual_Behavior':
                "Traffic shows minor-to-moderate deviation from baseline. "
                "May indicate legitimate change in usage or minor anomaly.",
            'Resembles_Known_Attack':
                "Traffic shows some resemblance to known attack patterns. "
                "Requires further investigation.",
            'Suspicious_Activity':
                "Traffic exhibits characteristics that warrant security review. "
                "Low immediate threat, but worth monitoring."
        }
        
        return assessments.get(threat_class, "Unknown threat classification")
    
    def _recommend_action(self, threat_class: str, suspicion_score: float) -> str:
        """
        Recommend defensive action based on fused signals
        """
        if threat_class == 'Known_Attack_Pattern' and suspicion_score > 0.8:
            return "ISOLATE_ENDPOINT"
        elif threat_class in ['Possible_Attack_With_Unusual_Behavior', 
                             'Resembles_Known_Attack'] and suspicion_score > 0.7:
            return "RATE_LIMIT_AND_MONITOR"
        elif threat_class == 'Unrecognized_Behavioral_Anomaly':
            return "PAUSE_AND_ALERT"
        elif threat_class == 'Unusual_Behavior' and suspicion_score > 0.6:
            return "MONITOR_CLOSELY"
        else:
            return "CONTINUE_MONITORING"
