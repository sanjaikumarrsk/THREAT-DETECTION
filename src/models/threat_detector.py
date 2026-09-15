"""
Model 1 - Known Threat Pattern Recognition
Recognizes resemblance to known malicious traffic patterns
"""
import logging
from typing import Dict, List, Any, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)

class ThreatDetector:
    """
    Model 1: Recognizes whether observed traffic closely resembles known malicious patterns
    Provides resemblance/similarity-style signal, not claiming to independently understand attacks
    """
    
    def __init__(self):
        # Simulated known attack signatures
        self.known_patterns = {
            'DDoS': {
                'characteristics': ['high_request_rate', 'similar_source_ips', 'high_volume'],
                'baseline_rps': 100,
                'confidence_threshold': 0.75
            },
            'Port_Scan': {
                'characteristics': ['sequential_ports', 'single_source', 'failed_connections'],
                'baseline_rps': 50,
                'confidence_threshold': 0.70
            },
            'Botnet': {
                'characteristics': ['periodic_outbound', 'command_callbacks', 'multiple_protocols'],
                'baseline_rps': 200,
                'confidence_threshold': 0.80
            },
            'Exploitation': {
                'characteristics': ['payload_detection', 'buffer_overflow_patterns', 'shellcode'],
                'baseline_rps': 10,
                'confidence_threshold': 0.85
            },
            'Reconnaissance': {
                'characteristics': ['dns_queries', 'failed_connections', 'service_probing'],
                'baseline_rps': 30,
                'confidence_threshold': 0.65
            }
        }
        
        logger.info("Threat Detector (Known Pattern Recognition) initialized")
    
    def detect_threat_resemblance(self, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze traffic for resemblance to known malicious patterns
        Returns resemblance scores for different attack types
        """
        resemblance_scores = self._calculate_resemblance(traffic_data)
        
        result = {
            'timestamp': datetime.utcnow().isoformat(),
            'entity_id': traffic_data.get('entity_id'),
            'resemblance_scores': resemblance_scores,
            'primary_threat': self._get_primary_threat(resemblance_scores),
            'confidence': max(resemblance_scores.values()) if resemblance_scores else 0,
            'model_type': 'known_pattern_recognition',
            'note': 'Scores indicate resemblance to known patterns, not confirmed attack type'
        }
        
        logger.debug(f"Threat resemblance analysis: {result['primary_threat']} "
                    f"({result['confidence']:.1%})")
        
        return result
    
    def _calculate_resemblance(self, traffic_data: Dict[str, Any]) -> Dict[str, float]:
        """Calculate resemblance score for each known attack type"""
        scores = {}
        
        # Extract traffic features
        request_rate = traffic_data.get('requests_per_minute', 0)
        outbound_volume = traffic_data.get('outbound_volume_mbps', 0)
        unique_destinations = traffic_data.get('unique_destinations', 0)
        failed_connections = traffic_data.get('failed_connections', 0)
        protocol_diversity = traffic_data.get('protocol_diversity', 0)
        
        # DDoS pattern matching
        ddos_score = 0.0
        if request_rate > 1000:  # High request rate
            ddos_score += 0.4
        if outbound_volume > 500:  # High volume
            ddos_score += 0.3
        if unique_destinations < 5:  # Focused targets
            ddos_score += 0.3
        scores['DDoS'] = min(ddos_score, 1.0)
        
        # Port Scan pattern matching
        portscan_score = 0.0
        if failed_connections > 500:  # Many failed connections
            portscan_score += 0.5
        if unique_destinations > 50:  # Multiple destination ports
            portscan_score += 0.3
        if request_rate > 500:
            portscan_score += 0.2
        scores['Port_Scan'] = min(portscan_score, 1.0)
        
        # Botnet pattern matching
        botnet_score = 0.0
        if protocol_diversity > 0.7:  # Multiple protocols
            botnet_score += 0.4
        if outbound_volume > 100:  # Outbound data exfiltration
            botnet_score += 0.3
        if request_rate > 200:
            botnet_score += 0.2
        if unique_destinations > 20:
            botnet_score += 0.1
        scores['Botnet'] = min(botnet_score, 1.0)
        
        # Reconnaissance pattern matching
        recon_score = 0.0
        if failed_connections > 100:
            recon_score += 0.3
        if unique_destinations > 10:  # Probing multiple services
            recon_score += 0.4
        if request_rate > 100:
            recon_score += 0.3
        scores['Reconnaissance'] = min(recon_score, 1.0)
        
        # Exploitation pattern matching (more conservative scoring)
        exploit_score = 0.0
        if 'payload_indicators' in str(traffic_data):
            exploit_score += 0.5
        scores['Exploitation'] = min(exploit_score, 1.0)
        
        # Normal traffic baseline
        normal_score = 1.0 - (sum(scores.values()) / len(scores)) if scores else 1.0
        scores['Normal'] = max(normal_score, 0.0)
        
        return scores
    
    def _get_primary_threat(self, resemblance_scores: Dict[str, float]) -> str:
        """Get the attack type with highest resemblance"""
        if not resemblance_scores:
            return 'Unknown'
        
        primary = max(resemblance_scores.items(), key=lambda x: x[1])
        return primary[0]
    
    def get_threat_explanation(self, traffic_data: Dict[str, Any], 
                              resemblance_scores: Dict[str, float]) -> Dict[str, Any]:
        """Provide explanation of why traffic resembles known patterns"""
        explanations = {
            'timestamp': datetime.utcnow().isoformat(),
            'factors': []
        }
        
        request_rate = traffic_data.get('requests_per_minute', 0)
        if request_rate > 1000:
            explanations['factors'].append({
                'factor': 'High Request Rate',
                'value': f"{request_rate} req/min",
                'relevance': 'Matches DDoS/Botnet characteristics'
            })
        
        outbound_volume = traffic_data.get('outbound_volume_mbps', 0)
        if outbound_volume > 100:
            explanations['factors'].append({
                'factor': 'High Outbound Volume',
                'value': f"{outbound_volume} MB/min",
                'relevance': 'Matches data exfiltration/botnet'
            })
        
        unique_destinations = traffic_data.get('unique_destinations', 0)
        if unique_destinations > 50:
            explanations['factors'].append({
                'factor': 'Multiple Destinations',
                'value': f"{unique_destinations} unique IPs",
                'relevance': 'Matches reconnaissance/scanning'
            })
        
        failed_connections = traffic_data.get('failed_connections', 0)
        if failed_connections > 500:
            explanations['factors'].append({
                'factor': 'High Failed Connections',
                'value': f"{failed_connections} failures",
                'relevance': 'Matches port scanning/exploitation attempts'
            })
        
        return explanations
