"""
Verification Engine - Closed-loop verification of defense effectiveness
"""
import logging
from typing import Dict, List, Any
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class VerificationEngine:
    """
    Verifies whether defensive responses actually reduced suspicious activity
    Implements closed-loop threat verification and escalation
    """
    
    def __init__(self):
        self.verification_log = []
        self.response_effectiveness = {}
        logger.info("Verification Engine initialized")
    
    def monitor_post_defense(self, entity_id: str, defense_id: str, 
                            pre_defense_metrics: Dict[str, Any],
                            post_defense_metrics: Dict[str, Any],
                            monitor_duration_minutes: int = 5) -> Dict[str, Any]:
        """
        Monitor entity activity after defensive response
        Compare pre- and post-defense metrics to verify effectiveness
        
        Expected metrics:
        - suspicious_connections_per_minute
        - suspicious_traffic_volume_mbps
        - threat_score
        """
        
        verification_result = {
            'verification_id': f"verify_{defense_id}",
            'entity_id': entity_id,
            'defense_id': defense_id,
            'timestamp': datetime.utcnow().isoformat(),
            'monitor_duration_minutes': monitor_duration_minutes,
            'pre_defense_metrics': pre_defense_metrics,
            'post_defense_metrics': post_defense_metrics
        }
        
        # Calculate changes
        metrics_improvement = self._calculate_improvement(pre_defense_metrics, post_defense_metrics)
        verification_result['metrics_improvement'] = metrics_improvement
        
        # Determine verification result
        if metrics_improvement['overall_improvement_percent'] > 80:
            verification_result['verification_status'] = 'THREAT_RESOLVED'
            verification_result['assessment'] = 'Defense effectively reduced suspicious activity'
            next_action = 'RESOLVE'
        elif metrics_improvement['overall_improvement_percent'] > 50:
            verification_result['verification_status'] = 'THREAT_REDUCED'
            verification_result['assessment'] = 'Suspicious activity decreased but may not be fully contained'
            next_action = 'CONTINUE_MONITORING'
        else:
            verification_result['verification_status'] = 'THREAT_PERSISTS'
            verification_result['assessment'] = 'Defense did not significantly reduce suspicious activity'
            next_action = 'ESCALATE'
        
        verification_result['next_action'] = next_action
        
        self.verification_log.append(verification_result)
        self._update_response_effectiveness(defense_id, metrics_improvement)
        
        logger.info(f"Verification for {entity_id}: {verification_result['verification_status']}")
        
        return verification_result
    
    def _calculate_improvement(self, pre_metrics: Dict[str, Any], 
                              post_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate improvement in metrics after defense"""
        improvements = {}
        
        # Connection rate improvement
        if 'suspicious_connections_per_minute' in pre_metrics:
            pre_conn = pre_metrics.get('suspicious_connections_per_minute', 1)
            post_conn = post_metrics.get('suspicious_connections_per_minute', 0)
            improvement = ((pre_conn - post_conn) / max(pre_conn, 1)) * 100
            improvements['connection_reduction_percent'] = max(improvement, 0)
        
        # Traffic volume improvement
        if 'suspicious_traffic_volume_mbps' in pre_metrics:
            pre_vol = pre_metrics.get('suspicious_traffic_volume_mbps', 1)
            post_vol = post_metrics.get('suspicious_traffic_volume_mbps', 0)
            improvement = ((pre_vol - post_vol) / max(pre_vol, 1)) * 100
            improvements['traffic_reduction_percent'] = max(improvement, 0)
        
        # Threat score improvement
        if 'threat_score' in pre_metrics:
            pre_threat = pre_metrics.get('threat_score', 1)
            post_threat = post_metrics.get('threat_score', 0)
            improvement = ((pre_threat - post_threat) / max(pre_threat, 1)) * 100
            improvements['threat_score_reduction_percent'] = max(improvement, 0)
        
        # Calculate overall improvement
        if improvements:
            overall = sum(improvements.values()) / len(improvements)
            improvements['overall_improvement_percent'] = round(overall, 1)
        else:
            improvements['overall_improvement_percent'] = 0
        
        return improvements
    
    def _update_response_effectiveness(self, defense_id: str, improvement: Dict[str, Any]) -> None:
        """Track effectiveness of responses for future tuning"""
        self.response_effectiveness[defense_id] = {
            'defense_id': defense_id,
            'improvement_percent': improvement.get('overall_improvement_percent', 0),
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def should_escalate(self, verification_result: Dict[str, Any]) -> bool:
        """Determine if threat requires escalation"""
        return verification_result.get('verification_status') == 'THREAT_PERSISTS'
    
    def get_verification_history(self, entity_id: str = None, hours: int = 24) -> List[Dict[str, Any]]:
        """Get verification history for entity or all entities"""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        history = []
        
        for verification in self.verification_log:
            v_time = datetime.fromisoformat(verification['timestamp'])
            if v_time >= cutoff_time:
                if entity_id is None or verification['entity_id'] == entity_id:
                    history.append(verification)
        
        return history
    
    def get_effectiveness_summary(self) -> Dict[str, Any]:
        """Get summary of response effectiveness"""
        if not self.response_effectiveness:
            return {
                'total_responses_verified': 0,
                'average_effectiveness': 0,
                'high_effectiveness_count': 0,
                'low_effectiveness_count': 0
            }
        
        effectiveness_scores = [r['improvement_percent'] for r in self.response_effectiveness.values()]
        
        return {
            'total_responses_verified': len(self.response_effectiveness),
            'average_effectiveness': round(sum(effectiveness_scores) / len(effectiveness_scores), 1),
            'high_effectiveness_count': sum(1 for s in effectiveness_scores if s > 80),
            'medium_effectiveness_count': sum(1 for s in effectiveness_scores if 50 <= s <= 80),
            'low_effectiveness_count': sum(1 for s in effectiveness_scores if s < 50),
            'last_update': datetime.utcnow().isoformat()
        }
