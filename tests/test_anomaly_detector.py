"""
Test suite for Anomaly Detector (Model 2)
"""
import pytest
from datetime import datetime
from src.models.anomaly_detector import AnomalyDetector

def test_anomaly_detector_initialization():
    """Test anomaly detector initialization"""
    detector = AnomalyDetector()
    assert detector is not None
    assert len(detector.entity_baselines) == 0

def test_baseline_establishment():
    """Test baseline establishment for entity"""
    detector = AnomalyDetector()
    
    baseline_metrics = {
        'requests_per_minute': 100,
        'outbound_volume_mbps': 10,
        'unique_destinations': 5,
        'failed_connections_per_minute': 2,
        'peak_hours': [9, 10, 11, 14, 15, 16],
        'protocol_distribution': {'TCP': 0.7, 'UDP': 0.2, 'ICMP': 0.1},
        'samples_used': 1000,
        'confidence': 0.85
    }
    
    result = detector.establish_baseline('Employee-PC-07', baseline_metrics)
    
    assert result['status'] == 'baseline_established'
    assert 'Employee-PC-07' in detector.entity_baselines

def test_normal_behavior_detection():
    """Test detection of normal behavioral activity"""
    detector = AnomalyDetector()
    
    # Establish baseline
    baseline_metrics = {
        'requests_per_minute': 100,
        'outbound_volume_mbps': 10,
        'unique_destinations': 5,
        'failed_connections_per_minute': 2,
        'peak_hours': [9, 10, 11, 14, 15, 16],
        'protocol_distribution': {'TCP': 0.7, 'UDP': 0.2, 'ICMP': 0.1}
    }
    detector.establish_baseline('Employee-PC-07', baseline_metrics)
    
    # Test normal activity
    current_metrics = {
        'requests_per_minute': 105,  # Slight variation
        'outbound_volume_mbps': 11,
        'unique_destinations': 5,
        'failed_connections_per_minute': 2,
        'protocols_used': ['TCP', 'UDP']
    }
    
    result = detector.detect_anomaly('Employee-PC-07', current_metrics, baseline_metrics)
    
    assert result['is_anomalous'] == False
    assert result['anomaly_score'] < 30

def test_anomalous_behavior_detection():
    """Test detection of anomalous behavioral activity"""
    detector = AnomalyDetector()
    
    # Establish baseline
    baseline_metrics = {
        'requests_per_minute': 100,
        'outbound_volume_mbps': 10,
        'unique_destinations': 5,
        'failed_connections_per_minute': 2,
        'peak_hours': [9, 10, 11, 14, 15, 16],
        'protocol_distribution': {'TCP': 0.7, 'UDP': 0.2}
    }
    detector.establish_baseline('Employee-PC-07', baseline_metrics)
    
    # Test anomalous activity (significant deviations)
    current_metrics = {
        'requests_per_minute': 8500,  # Huge increase
        'outbound_volume_mbps': 1200,  # Huge increase
        'unique_destinations': 400,  # Many more destinations
        'failed_connections_per_minute': 1100,  # Huge increase
        'protocols_used': ['TCP', 'UDP', 'SSH', 'HTTPS']
    }
    
    result = detector.detect_anomaly('Employee-PC-07', current_metrics, baseline_metrics)
    
    assert result['is_anomalous'] == True
    assert result['anomaly_score'] > 70
    assert 'traffic_volume' in result['deviations']

def test_baseline_protection_from_suspicious_traffic():
    """Test that suspicious traffic cannot update baseline"""
    detector = AnomalyDetector()
    
    baseline_metrics = {
        'requests_per_minute': 100,
        'outbound_volume_mbps': 10
    }
    
    suspicious_metrics = {
        'requests_per_minute': 9000,
        'outbound_volume_mbps': 1200
    }
    
    # Should not update baseline from suspicious traffic
    result = detector.should_update_baseline(
        'Employee-PC-07',
        suspicious_metrics,
        is_suspicious=True
    )
    
    assert result == False

def test_anomaly_explanation():
    """Test anomaly explanation generation"""
    detector = AnomalyDetector()
    
    deviations = {
        'traffic_volume': 95,
        'outbound_volume': 92,
        'destination_diversity': 85,
        'failed_connections': 88,
        'time_of_day': 10,
        'protocol_deviation': 0
    }
    
    explanation = detector.get_anomaly_explanation('Employee-PC-07', deviations)
    
    assert 'contributing_factors' in explanation
    assert len(explanation['contributing_factors']) > 0
    # Should have top factors sorted by impact
    assert explanation['contributing_factors'][0]['deviation_percentage'] >= explanation['contributing_factors'][1]['deviation_percentage']
