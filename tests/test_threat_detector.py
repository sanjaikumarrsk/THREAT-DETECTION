"""
Test suite for Threat Detector (Model 1)
"""
import pytest
from datetime import datetime
from src.models.threat_detector import ThreatDetector

def test_threat_detector_initialization():
    """Test threat detector initialization"""
    detector = ThreatDetector()
    assert detector is not None
    assert 'DDoS' in detector.known_patterns
    assert 'Port_Scan' in detector.known_patterns

def test_ddos_pattern_detection():
    """Test DDoS attack pattern recognition"""
    detector = ThreatDetector()
    
    traffic_data = {
        'entity_id': 'Server-01',
        'requests_per_minute': 5000,
        'outbound_volume_mbps': 600,
        'unique_destinations': 2,
        'failed_connections': 100
    }
    
    result = detector.detect_threat_resemblance(traffic_data)
    
    assert result['resemblance_scores']['DDoS'] > 0.7
    assert result['primary_threat'] == 'DDoS'
    assert result['confidence'] > 0.7

def test_port_scan_pattern_detection():
    """Test port scanning pattern recognition"""
    detector = ThreatDetector()
    
    traffic_data = {
        'entity_id': 'Attacker-IP',
        'requests_per_minute': 800,
        'outbound_volume_mbps': 50,
        'unique_destinations': 150,
        'failed_connections': 1500
    }
    
    result = detector.detect_threat_resemblance(traffic_data)
    
    assert result['resemblance_scores']['Port_Scan'] > 0.6
    assert result['primary_threat'] == 'Port_Scan'

def test_normal_traffic_detection():
    """Test normal traffic identification"""
    detector = ThreatDetector()
    
    traffic_data = {
        'entity_id': 'Normal-User',
        'requests_per_minute': 50,
        'outbound_volume_mbps': 10,
        'unique_destinations': 5,
        'failed_connections': 2
    }
    
    result = detector.detect_threat_resemblance(traffic_data)
    
    assert result['resemblance_scores']['Normal'] > 0.8
    assert result['primary_threat'] == 'Normal'
    assert result['confidence'] < 0.3

def test_threat_explanation():
    """Test threat explanation generation"""
    detector = ThreatDetector()
    
    traffic_data = {
        'entity_id': 'Server-01',
        'requests_per_minute': 3000,
        'outbound_volume_mbps': 400,
        'unique_destinations': 20,
        'failed_connections': 500
    }
    
    result = detector.detect_threat_resemblance(traffic_data)
    explanation = detector.get_threat_explanation(traffic_data, result['resemblance_scores'])
    
    assert 'factors' in explanation
    assert len(explanation['factors']) > 0
    assert 'High Request Rate' in str(explanation)
