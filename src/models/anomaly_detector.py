"""
Model 2 - Organization-Specific Behavioral Anomaly Detection
Learns normal behavior and identifies deviations
"""
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import numpy as np

logger = logging.getLogger(__name__)

class AnomalyDetector:
    """
    Model 2: Learns organization-specific normal behavior and detects deviations
    Does NOT automatically label unfamiliar behavior as confirmed zero-day attacks
    Reports suspicious behavioral deviation instead
    """
    
    def __init__(self):
        self.entity_baselines = {}
        self.deviation_history = []
        
        logger.info("Anomaly Detector (Behavioral Baseline) initialized")
    
    def establish_baseline(self, entity_id: str, baseline_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """
        Establish normal behavioral baseline for an entity
        
        Expected metrics:
        - requests_per_minute (average)
        - outbound_volume_mbps (average)
        - unique_destinations (typical count)
        - failed_connections_per_minute (baseline)
        - time_of_day_pattern (e.g., peak hours)
        - day_of_week_pattern
        - protocol_distribution
        """
        self.entity_baselines[entity_id] = {
            'entity_id': entity_id,
            'baseline_metrics': baseline_metrics,
            'established_at': datetime.utcnow().isoformat(),
            'samples_used': baseline_metrics.get('samples_used', 1000),
            'confidence': baseline_metrics.get('confidence', 0.85),
            'trusted': True  # Only update from trusted/normal traffic
        }
        
        logger.info(f"Baseline established for entity: {entity_id}")
        
        return {
            'status': 'baseline_established',
            'entity_id': entity_id,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def detect_anomaly(self, entity_id: str, current_metrics: Dict[str, Any], 
                      baseline_metrics: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Compare current behavior against baseline to detect anomalies
        Returns deviation score and explanation
        """
        if baseline_metrics is None:
            baseline_metrics = self.entity_baselines.get(entity_id, {}).get('baseline_metrics')
        
        if baseline_metrics is None:
            logger.warning(f"No baseline available for entity: {entity_id}")
            return {
                'status': 'no_baseline',
                'entity_id': entity_id,
                'can_detect_anomaly': False
            }
        
        # Calculate deviations for each behavioral dimension
        deviations = self._calculate_deviations(current_metrics, baseline_metrics)
        anomaly_score = self._calculate_anomaly_score(deviations)
        
        result = {
            'timestamp': datetime.utcnow().isoformat(),
            'entity_id': entity_id,
            'anomaly_score': anomaly_score,  # 0-100 scale
            'is_anomalous': anomaly_score > 70,
            'deviations': deviations,
            'assessment': self._get_assessment(anomaly_score),
            'model_type': 'behavioral_anomaly_detection',
            'note': 'High deviation indicates unusual behavior, not confirmed attack'
        }
        
        # Store deviation history
        self.deviation_history.append({
            'entity_id': entity_id,
            'timestamp': datetime.utcnow().isoformat(),
            'anomaly_score': anomaly_score,
            'is_anomalous': result['is_anomalous']
        })
        
        logger.debug(f"Anomaly detection for {entity_id}: score={anomaly_score:.1f}, "
                    f"assessment={result['assessment']}")
        
        return result
    
    def _calculate_deviations(self, current: Dict[str, Any], 
                              baseline: Dict[str, Any]) -> Dict[str, float]:
        """Calculate deviation percentage for each behavioral dimension"""
        deviations = {}
        
        # Traffic volume deviation
        if 'requests_per_minute' in baseline:
            baseline_rps = baseline['requests_per_minute']
            current_rps = current.get('requests_per_minute', baseline_rps)
            deviation = abs(current_rps - baseline_rps) / max(baseline_rps, 1) * 100
            deviations['traffic_volume'] = min(deviation, 100)
        
        # Outbound volume deviation
        if 'outbound_volume_mbps' in baseline:
            baseline_out = baseline['outbound_volume_mbps']
            current_out = current.get('outbound_volume_mbps', baseline_out)
            deviation = abs(current_out - baseline_out) / max(baseline_out, 1) * 100
            deviations['outbound_volume'] = min(deviation, 100)
        
        # Destination diversity deviation
        if 'unique_destinations' in baseline:
            baseline_dest = baseline['unique_destinations']
            current_dest = current.get('unique_destinations', baseline_dest)
            deviation = abs(current_dest - baseline_dest) / max(baseline_dest, 1) * 100
            deviations['destination_diversity'] = min(deviation, 100)
        
        # Connection frequency deviation
        if 'failed_connections_per_minute' in baseline:
            baseline_fail = baseline['failed_connections_per_minute']
            current_fail = current.get('failed_connections_per_minute', baseline_fail)
            deviation = abs(current_fail - baseline_fail) / max(baseline_fail, 1) * 100
            deviations['failed_connections'] = min(deviation, 100)
        
        # Time-of-day deviation
        current_hour = datetime.utcnow().hour
        baseline_peak_hours = baseline.get('peak_hours', [9, 10, 11, 14, 15, 16])
        if current_hour not in baseline_peak_hours:
            deviations['time_of_day'] = 50  # Moderate deviation for off-peak access
        else:
            deviations['time_of_day'] = 0
        
        # Protocol diversity deviation
        if 'protocol_distribution' in baseline and 'protocols_used' in current:
            baseline_protocols = set(baseline.get('protocol_distribution', {}).keys())
            current_protocols = set(current.get('protocols_used', []))
            new_protocols = current_protocols - baseline_protocols
            if new_protocols:
                deviations['protocol_deviation'] = min(len(new_protocols) * 20, 100)
            else:
                deviations['protocol_deviation'] = 0
        
        return deviations
    
    def _calculate_anomaly_score(self, deviations: Dict[str, float]) -> float:
        """
        Calculate overall anomaly score (0-100)
        Weighs different deviations appropriately
        """
        if not deviations:
            return 0.0
        
        # Weighted scoring: impact factors
        weights = {
            'traffic_volume': 0.25,
            'outbound_volume': 0.25,
            'destination_diversity': 0.20,
            'failed_connections': 0.20,
            'time_of_day': 0.05,
            'protocol_deviation': 0.05
        }
        
        weighted_score = 0.0
        for dimension, deviation in deviations.items():
            weight = weights.get(dimension, 0.0)
            weighted_score += deviation * weight
        
        return min(weighted_score, 100.0)
    
    def _get_assessment(self, anomaly_score: float) -> str:
        """Get human-readable assessment of anomaly"""
        if anomaly_score < 30:
            return "Normal behavior"
        elif anomaly_score < 50:
            return "Minor deviation"
        elif anomaly_score < 70:
            return "Moderate deviation"
        elif anomaly_score < 85:
            return "Significant deviation - suspicious behavior"
        else:
            return "Severe deviation - unusual/previously unseen behavior"
    
    def get_anomaly_explanation(self, entity_id: str, deviations: Dict[str, float]) -> Dict[str, Any]:
        """Provide detailed explanation of anomalies"""
        explanation = {
            'timestamp': datetime.utcnow().isoformat(),
            'entity_id': entity_id,
            'contributing_factors': []
        }
        
        # Sort by magnitude of deviation
        sorted_deviations = sorted(deviations.items(), key=lambda x: x[1], reverse=True)
        
        for dimension, deviation in sorted_deviations[:5]:  # Top 5 factors
            if deviation > 0:
                explanation['contributing_factors'].append({
                    'factor': self._humanize_dimension(dimension),
                    'deviation_percentage': round(deviation, 1),
                    'impact': self._get_impact_level(deviation)
                })
        
        return explanation
    
    def _humanize_dimension(self, dimension: str) -> str:
        """Convert dimension name to human-readable format"""
        mapping = {
            'traffic_volume': 'Traffic Volume',
            'outbound_volume': 'Outbound Data Transfer',
            'destination_diversity': 'Unique Destinations',
            'failed_connections': 'Failed Connection Attempts',
            'time_of_day': 'Time-of-Day Pattern',
            'protocol_deviation': 'Unusual Protocols'
        }
        return mapping.get(dimension, dimension)
    
    def _get_impact_level(self, deviation: float) -> str:
        """Get impact level for a deviation"""
        if deviation < 20:
            return "Minor"
        elif deviation < 50:
            return "Moderate"
        elif deviation < 80:
            return "Significant"
        else:
            return "Critical"
    
    def should_update_baseline(self, entity_id: str, current_metrics: Dict[str, Any],
                               is_suspicious: bool) -> bool:
        """
        Determine if baseline should be updated
        CRITICAL: Never update baseline from suspicious traffic
        """
        if is_suspicious:
            logger.warning(f"Blocking baseline update for {entity_id}: traffic is suspicious")
            return False
        
        # Only update from trusted/normal traffic
        logger.info(f"Baseline update allowed for {entity_id}: traffic appears normal")
        return True
    
    def get_entity_status(self, entity_id: str) -> Dict[str, Any]:
        """Get current behavioral status of an entity"""
        baseline = self.entity_baselines.get(entity_id)
        
        if not baseline:
            return {
                'entity_id': entity_id,
                'status': 'no_baseline',
                'has_baseline': False
            }
        
        recent_deviations = [d for d in self.deviation_history 
                           if d['entity_id'] == entity_id]
        
        avg_score = np.mean([d['anomaly_score'] for d in recent_deviations]) if recent_deviations else 0
        
        return {
            'entity_id': entity_id,
            'has_baseline': True,
            'baseline_established': baseline['established_at'],
            'average_anomaly_score': round(avg_score, 2),
            'recent_alerts': sum(1 for d in recent_deviations[-10:] if d['is_anomalous']),
            'status': 'monitored'
        }
