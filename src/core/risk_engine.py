"""
Risk Engine - Converts threat/anomaly signals into risk assessment and recommended response
"""
import logging
from typing import Dict, List, Any
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)

class ResponseType(Enum):
    MONITOR = "monitor"
    RATE_LIMIT = "rate_limit"
    PAUSE = "pause"
    ISOLATE = "isolate"
    TERMINATE = "terminate"

class RiskEngine:
    """
    Converts threat evidence into risk assessment and defensive recommendations
    Separates AI detection from operational defense decisions
    
    Flow:
    AI pattern recognition → Threat/behavioral evidence → Risk assessment →
    Security policy → Recommended defensive action → User authorization
    """
    
    def __init__(self):
        self.response_policies = self._initialize_policies()
        self.risk_log = []
        logger.info("Risk Engine initialized")
    
    def assess_risk(self, threat_fusion: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assess risk level based on threat fusion output and asset/business factors
        
        Factors considered:
        - Attack confidence
        - Behavioral deviation
        - Asset criticality
        - Potential impact
        - Attack persistence
        - Business impact
        - Response cost
        - Action reversibility
        """
        entity_id = threat_fusion.get('entity_id')
        suspicion_score = threat_fusion.get('combined_suspicion_score', 0)
        threat_class = threat_fusion.get('threat_classification', 'Unknown')
        
        # Calculate risk factors
        risk_factors = self._calculate_risk_factors(threat_fusion)
        
        # Determine risk level
        risk_level = self._determine_risk_level(risk_factors)
        
        # Select recommended response
        recommended_response = self._select_response(risk_level, threat_class, risk_factors)
        
        risk_assessment = {
            'timestamp': datetime.utcnow().isoformat(),
            'entity_id': entity_id,
            'risk_level': risk_level,
            'suspicion_score': round(suspicion_score, 3),
            'threat_classification': threat_class,
            'risk_factors': risk_factors,
            'recommended_response': recommended_response,
            'requires_authorization': True,
            'authorization_timeout_seconds': 300 if risk_level == 'HIGH' else 600
        }
        
        self.risk_log.append(risk_assessment)
        logger.info(f"Risk assessment for {entity_id}: {risk_level}")
        
        return risk_assessment
    
    def _calculate_risk_factors(self, threat_fusion: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate individual risk factors"""
        suspicion = threat_fusion.get('combined_suspicion_score', 0) * 100
        threat_class = threat_fusion.get('threat_classification', '')
        
        factors = {}
        
        # Attack confidence factor
        factors['attack_confidence'] = suspicion
        
        # Behavioral deviation factor
        anomaly_signal = threat_fusion.get('anomaly_signal', {})
        factors['behavioral_deviation'] = anomaly_signal.get('anomaly_score', 0)
        
        # Asset criticality (default to medium)
        factors['asset_criticality'] = 50  # 0-100 scale
        
        # Potential impact factor (based on threat class)
        if 'Known_Attack' in threat_class:
            factors['potential_impact'] = 85
        elif 'Unusual_Behavior' in threat_class:
            factors['potential_impact'] = 60
        else:
            factors['potential_impact'] = 40
        
        # Attack persistence factor (assume single event for now)
        factors['attack_persistence'] = 30
        
        # Business impact (moderate by default)
        factors['business_impact'] = 50
        
        return factors
    
    def _determine_risk_level(self, risk_factors: Dict[str, float]) -> str:
        """Determine overall risk level"""
        avg_factor = sum(risk_factors.values()) / len(risk_factors) if risk_factors else 0
        
        if avg_factor > 75:
            return "CRITICAL"
        elif avg_factor > 60:
            return "HIGH"
        elif avg_factor > 40:
            return "MEDIUM"
        elif avg_factor > 20:
            return "LOW"
        else:
            return "MINIMAL"
    
    def _select_response(self, risk_level: str, threat_class: str, 
                        risk_factors: Dict[str, float]) -> Dict[str, Any]:
        """
        Select defensive response based on risk assessment
        Consider reversibility and operational impact
        """
        responses = {
            'CRITICAL': {
                'primary': ResponseType.ISOLATE,
                'fallback': ResponseType.PAUSE,
                'description': 'Isolate endpoint from network to contain threat'
            },
            'HIGH': {
                'primary': ResponseType.PAUSE,
                'fallback': ResponseType.RATE_LIMIT,
                'description': 'Pause suspicious process with user authorization'
            },
            'MEDIUM': {
                'primary': ResponseType.RATE_LIMIT,
                'fallback': ResponseType.MONITOR,
                'description': 'Rate limit suspicious activity and monitor closely'
            },
            'LOW': {
                'primary': ResponseType.MONITOR,
                'fallback': ResponseType.MONITOR,
                'description': 'Continue monitoring, no immediate action required'
            },
            'MINIMAL': {
                'primary': ResponseType.MONITOR,
                'fallback': ResponseType.MONITOR,
                'description': 'No threat detected, continue normal monitoring'
            }
        }
        
        response = responses.get(risk_level, responses['LOW'])
        
        return {
            'risk_level': risk_level,
            'primary_action': response['primary'].value,
            'fallback_action': response['fallback'].value,
            'description': response['description'],
            'reversible': response['primary'] != ResponseType.TERMINATE,
            'operational_impact': self._estimate_operational_impact(response['primary']),
            'security_benefit': self._estimate_security_benefit(risk_factors)
        }
    
    def _estimate_operational_impact(self, response_type: ResponseType) -> str:
        """Estimate operational impact of response"""
        impacts = {
            ResponseType.MONITOR: "None - monitoring only",
            ResponseType.RATE_LIMIT: "Low - traffic limited but functional",
            ResponseType.PAUSE: "Medium - process paused, may affect users",
            ResponseType.ISOLATE: "High - endpoint isolated from network",
            ResponseType.TERMINATE: "Critical - process/connection terminated"
        }
        return impacts.get(response_type, "Unknown")
    
    def _estimate_security_benefit(self, risk_factors: Dict[str, float]) -> str:
        """Estimate security benefit of response"""
        avg_risk = sum(risk_factors.values()) / len(risk_factors) if risk_factors else 0
        
        if avg_risk > 75:
            return "Critical - stops high-confidence threat"
        elif avg_risk > 60:
            return "High - reduces significant threat"
        elif avg_risk > 40:
            return "Moderate - mitigates medium threat"
        else:
            return "Low - precautionary measure"
    
    def compare_response_options(self, entity_id: str, risk_level: str) -> List[Dict[str, Any]]:
        """
        Compare possible response options to find safest appropriate action
        
        This is a high-value feature that shows different trade-offs
        """
        options = []
        
        # Option 1: Continue monitoring
        options.append({
            'action': 'Continue Monitoring',
            'security_impact': 'Low - allows threat to continue',
            'business_impact': 'None - no disruption',
            'reversibility': 'N/A',
            'recommended': False
        })
        
        # Option 2: Rate limit
        options.append({
            'action': 'Rate Limit',
            'security_impact': 'Medium - slows attack/anomaly',
            'business_impact': 'Low - may affect throughput',
            'reversibility': 'Fully reversible',
            'recommended': risk_level in ['MEDIUM', 'LOW']
        })
        
        # Option 3: Pause
        options.append({
            'action': 'Pause Process',
            'security_impact': 'High - stops suspicious activity',
            'business_impact': 'Medium - process stops',
            'reversibility': 'Fully reversible - user can resume',
            'recommended': risk_level in ['HIGH', 'CRITICAL']
        })
        
        # Option 4: Isolate
        options.append({
            'action': 'Isolate Endpoint',
            'security_impact': 'Critical - removes threat from network',
            'business_impact': 'High - endpoint loses connectivity',
            'reversibility': 'Fully reversible - can reconnect after verification',
            'recommended': risk_level == 'CRITICAL'
        })
        
        return options
    
    def get_risk_recommendations(self) -> Dict[str, Any]:
        """Get summary of risk assessment recommendations"""
        if not self.risk_log:
            return {
                'total_assessments': 0,
                'critical_risks': 0,
                'high_risks': 0,
                'medium_risks': 0,
                'status': 'No risk assessments yet'
            }
        
        risk_levels = {}
        for assessment in self.risk_log:
            level = assessment['risk_level']
            risk_levels[level] = risk_levels.get(level, 0) + 1
        
        return {
            'total_assessments': len(self.risk_log),
            'critical_risks': risk_levels.get('CRITICAL', 0),
            'high_risks': risk_levels.get('HIGH', 0),
            'medium_risks': risk_levels.get('MEDIUM', 0),
            'low_risks': risk_levels.get('LOW', 0),
            'minimal_risks': risk_levels.get('MINIMAL', 0),
            'last_assessment': self.risk_log[-1]['timestamp'] if self.risk_log else None
        }
    
    def _initialize_policies(self) -> Dict[str, Dict]:
        """Initialize default security policies"""
        return {
            'default': {
                'name': 'Default Security Policy',
                'critical_timeout_seconds': 120,
                'high_timeout_seconds': 300,
                'medium_timeout_seconds': 600,
                'fail_safe_action': 'PAUSE',
                'require_approval': True
            }
        }


class IncidentEngine:
    """
    Creates incident stories from correlated alerts
    Groups related alerts into cohesive attack narratives
    """
    
    def __init__(self):
        self.incidents = {}
        self.alert_correlation_window = 300  # 5 minutes in seconds
        logger.info("Incident Engine initialized")
    
    def correlate_alerts(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Correlate multiple alerts into incident story
        Attack chain: reconnaissance → scanning → exploitation → lateral movement → exfiltration
        """
        if not alerts:
            return {'incidents': []}
        
        # Group alerts by entity and time window
        incident_groups = self._group_alerts(alerts)
        
        incidents = []
        for group_id, group_alerts in incident_groups.items():
            incident = self._create_incident_story(group_alerts)
            incidents.append(incident)
            self.incidents[group_id] = incident
        
        return {
            'incidents': incidents,
            'total_incidents': len(incidents),
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def _group_alerts(self, alerts: List[Dict[str, Any]]) -> Dict[str, List]:
        """Group alerts by entity and temporal proximity"""
        groups = {}
        
        for alert in alerts:
            entity_id = alert.get('entity_id', 'unknown')
            
            if entity_id not in groups:
                groups[entity_id] = []
            
            groups[entity_id].append(alert)
        
        return groups
    
    def _create_incident_story(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create coherent incident narrative from alerts"""
        if not alerts:
            return {}
        
        entity_id = alerts[0].get('entity_id', 'unknown')
        
        # Sort alerts by timestamp
        sorted_alerts = sorted(alerts, key=lambda x: x.get('timestamp', ''))
        
        story = {
            'incident_id': f"incident_{entity_id}_{int(datetime.utcnow().timestamp())}",
            'entity_id': entity_id,
            'alert_count': len(alerts),
            'start_time': sorted_alerts[0].get('timestamp'),
            'end_time': sorted_alerts[-1].get('timestamp'),
            'attack_chain': self._infer_attack_chain(sorted_alerts),
            'severity': self._assess_incident_severity(sorted_alerts),
            'alerts': sorted_alerts
        }
        
        return story
    
    def _infer_attack_chain(self, alerts: List[Dict[str, Any]]) -> List[str]:
        """Infer attack chain from alert sequence"""
        chain = []
        threat_classes = [a.get('threat_classification', '') for a in alerts]
        
        if any('Reconnaissance' in t for t in threat_classes):
            chain.append("Reconnaissance detected")
        
        if any('Port_Scan' in t or 'scanning' in t.lower() for t in threat_classes):
            chain.append("Port scanning detected")
        
        if any('Credential' in t or 'login' in t.lower() for t in threat_classes):
            chain.append("Credential attack detected")
        
        if any('lateral' in t.lower() for t in threat_classes):
            chain.append("Lateral movement detected")
        
        if any('data' in t.lower() or 'exfiltration' in t.lower() for t in threat_classes):
            chain.append("Possible data-transfer anomaly")
        
        return chain if chain else ["Correlated attack activity"]
    
    def _assess_incident_severity(self, alerts: List[Dict[str, Any]]) -> str:
        """Assess overall incident severity"""
        high_count = sum(1 for a in alerts if a.get('risk_level') == 'HIGH')
        critical_count = sum(1 for a in alerts if a.get('risk_level') == 'CRITICAL')
        
        if critical_count > 0:
            return "CRITICAL"
        elif high_count > 2:
            return "HIGH"
        elif high_count > 0:
            return "MEDIUM"
        else:
            return "LOW"
