"""
Data Collector - Securely collects network traffic and security telemetry
"""
import logging
from datetime import datetime
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class DataCollector:
    """Collects and normalizes network traffic and security telemetry"""
    
    def __init__(self):
        self.collection_log = []
        self.is_collecting = False
        self.source_filters = []
    
    def start_collection(self, sources: List[str] = None):
        """Start collecting data from specified sources"""
        self.is_collecting = True
        self.source_filters = sources or ['network', 'firewall', 'ids', 'endpoints']
        logger.info(f"Data collection started for sources: {self.source_filters}")
        return {
            'status': 'started',
            'timestamp': datetime.utcnow().isoformat(),
            'sources': self.source_filters
        }
    
    def stop_collection(self):
        """Stop data collection"""
        self.is_collecting = False
        logger.info("Data collection stopped")
        return {
            'status': 'stopped',
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def collect_network_traffic(self, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Collect and normalize network traffic data
        
        Expected format:
        {
            'source_ip': '192.168.1.100',
            'dest_ip': '10.0.0.1',
            'source_port': 52341,
            'dest_port': 443,
            'protocol': 'TCP',
            'bytes_sent': 1024,
            'bytes_received': 2048,
            'flags': 'SYN',
            'timestamp': datetime,
            'entity_id': 'Employee-PC-07'  # Device/entity identifier
        }
        """
        if not self.is_collecting:
            logger.warning("Collection not active")
            return None
        
        normalized = {
            'source_ip': traffic_data.get('source_ip'),
            'dest_ip': traffic_data.get('dest_ip'),
            'source_port': traffic_data.get('source_port'),
            'dest_port': traffic_data.get('dest_port'),
            'protocol': traffic_data.get('protocol', 'TCP'),
            'bytes_sent': traffic_data.get('bytes_sent', 0),
            'bytes_received': traffic_data.get('bytes_received', 0),
            'flags': traffic_data.get('flags'),
            'timestamp': traffic_data.get('timestamp', datetime.utcnow()),
            'entity_id': traffic_data.get('entity_id', 'unknown'),
            'collection_source': 'network_traffic'
        }
        
        self.collection_log.append(normalized)
        return normalized
    
    def collect_security_logs(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Collect security event logs"""
        if not self.is_collecting:
            return None
        
        normalized = {
            'event_type': log_data.get('event_type'),
            'entity_id': log_data.get('entity_id'),
            'user': log_data.get('user'),
            'source': log_data.get('source'),
            'action': log_data.get('action'),
            'result': log_data.get('result'),
            'timestamp': log_data.get('timestamp', datetime.utcnow()),
            'details': log_data.get('details', {}),
            'collection_source': 'security_logs'
        }
        
        self.collection_log.append(normalized)
        return normalized
    
    def get_collection_status(self) -> Dict[str, Any]:
        """Get current collection status"""
        return {
            'is_collecting': self.is_collecting,
            'sources_monitored': self.source_filters,
            'total_collected': len(self.collection_log),
            'last_update': datetime.utcnow().isoformat()
        }
    
    def get_recent_data(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent collected data"""
        return self.collection_log[-limit:] if self.collection_log else []
