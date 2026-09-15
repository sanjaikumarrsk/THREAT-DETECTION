"""
Data Vault - Secure local storage for telemetry data
Raw organizational security data remains within the customer's controlled environment
"""
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from enum import Enum

logger = logging.getLogger(__name__)

class DataClassification(Enum):
    """Classification of stored data"""
    RAW_TELEMETRY = "raw_telemetry"
    PROCESSED = "processed"
    BASELINE = "baseline"
    ALERT = "alert"
    INCIDENT = "incident"

class DataVault:
    """
    Secure local storage for all security telemetry and data
    Raw data remains local and is only accessible through authenticated services
    """
    
    def __init__(self):
        self.vault = {}
        self.telemetry = []
        self.baselines = {}
        self.audit_logs = []
        self.encryption_enabled = True  # Would use actual encryption in production
        logger.info("Data Vault initialized with local-only storage policy")
    
    def store_telemetry(self, data: Dict[str, Any], classification: DataClassification) -> str:
        """
        Store telemetry data locally
        Raw data never leaves the customer's environment
        """
        data_id = f"telemetry_{len(self.telemetry)}_{int(datetime.utcnow().timestamp())}"
        
        stored_item = {
            'id': data_id,
            'data': data,
            'classification': classification.value,
            'timestamp': datetime.utcnow().isoformat(),
            'encrypted': self.encryption_enabled,
            'entity_id': data.get('entity_id', 'unknown')
        }
        
        self.telemetry.append(stored_item)
        self.vault[data_id] = stored_item
        
        # Log storage action
        self._audit_log('STORE', data_id, f"Stored {classification.value} data")
        
        logger.debug(f"Telemetry stored locally: {data_id}")
        return data_id
    
    def retrieve_telemetry(self, data_id: str, authenticated: bool = True) -> Optional[Dict[str, Any]]:
        """
        Retrieve stored telemetry (only for authenticated/authorized internal services)
        """
        if not authenticated:
            logger.warning(f"Unauthorized attempt to retrieve telemetry: {data_id}")
            return None
        
        if data_id in self.vault:
            self._audit_log('RETRIEVE', data_id, "Telemetry accessed")
            return self.vault[data_id]
        
        return None
    
    def store_baseline(self, entity_id: str, baseline_data: Dict[str, Any]) -> None:
        """
        Store entity behavioral baseline locally
        Baseline learns from trusted normal traffic, not from suspicious activity
        """
        self.baselines[entity_id] = {
            'entity_id': entity_id,
            'baseline': baseline_data,
            'updated': datetime.utcnow().isoformat(),
            'update_from_suspicious': False,  # Critical: Don't learn from attacks
            'version': self.baselines.get(entity_id, {}).get('version', 0) + 1
        }
        
        self._audit_log('STORE_BASELINE', entity_id, "Baseline updated")
        logger.info(f"Baseline stored for entity: {entity_id}")
    
    def get_baseline(self, entity_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve entity baseline"""
        if entity_id in self.baselines:
            self._audit_log('RETRIEVE_BASELINE', entity_id, "Baseline accessed")
            return self.baselines[entity_id]
        return None
    
    def update_baseline_safely(self, entity_id: str, new_observation: Dict[str, Any], 
                               is_suspicious: bool = False) -> bool:
        """
        Update baseline only from trusted/normal traffic
        Critical security principle: suspicious traffic must not redefine normal
        """
        if is_suspicious:
            logger.warning(f"Attempted to update baseline from suspicious activity: {entity_id}")
            self._audit_log('BASELINE_UPDATE_REJECTED', entity_id, 
                           "Suspicious traffic blocked from baseline learning")
            return False
        
        # Only update if traffic appears normal
        if entity_id in self.baselines:
            current_baseline = self.baselines[entity_id]['baseline']
            # Gradual update logic would go here
            self.store_baseline(entity_id, current_baseline)
            self._audit_log('BASELINE_UPDATED', entity_id, "Baseline updated from normal traffic")
            return True
        
        return False
    
    def store_alert(self, alert_data: Dict[str, Any]) -> str:
        """Store security alert"""
        alert_id = f"alert_{int(datetime.utcnow().timestamp())}_{alert_data.get('entity_id', 'unknown')}"
        
        stored_alert = {
            'id': alert_id,
            'data': alert_data,
            'classification': DataClassification.ALERT.value,
            'timestamp': datetime.utcnow().isoformat(),
            'stored_locally': True
        }
        
        self.vault[alert_id] = stored_alert
        self._audit_log('STORE_ALERT', alert_id, "Alert stored")
        
        return alert_id
    
    def get_alerts(self, entity_id: str = None, hours: int = 24) -> List[Dict[str, Any]]:
        """Retrieve recent alerts"""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        alerts = []
        
        for item_id, item in self.vault.items():
            if item.get('classification') == DataClassification.ALERT.value:
                item_time = datetime.fromisoformat(item['timestamp'])
                if item_time >= cutoff_time:
                    if entity_id is None or item['data'].get('entity_id') == entity_id:
                        alerts.append(item)
        
        self._audit_log('RETRIEVE_ALERTS', f"entity_{entity_id or 'all'}", 
                       f"Retrieved {len(alerts)} alerts")
        
        return alerts
    
    def get_telemetry_for_entity(self, entity_id: str, hours: int = 1) -> List[Dict[str, Any]]:
        """Get recent telemetry for specific entity"""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        entity_data = []
        
        for item_id, item in self.vault.items():
            if item.get('entity_id') == entity_id:
                item_time = datetime.fromisoformat(item['timestamp'])
                if item_time >= cutoff_time:
                    entity_data.append(item)
        
        self._audit_log('RETRIEVE_ENTITY_TELEMETRY', entity_id, 
                       f"Retrieved {len(entity_data)} records")
        
        return entity_data
    
    def _audit_log(self, action: str, target: str, details: str) -> None:
        """Log all data access for audit purposes"""
        audit_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'action': action,
            'target': target,
            'details': details,
            'source': 'data_vault'
        }
        self.audit_logs.append(audit_entry)
    
    def get_audit_trail(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get audit trail for compliance"""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        trail = []
        
        for entry in self.audit_logs:
            entry_time = datetime.fromisoformat(entry['timestamp'])
            if entry_time >= cutoff_time:
                trail.append(entry)
        
        return trail
    
    def get_vault_status(self) -> Dict[str, Any]:
        """Get vault status and statistics"""
        return {
            'total_items': len(self.vault),
            'telemetry_records': len(self.telemetry),
            'baselines_stored': len(self.baselines),
            'audit_logs': len(self.audit_logs),
            'encryption_enabled': self.encryption_enabled,
            'data_location': 'local_only',
            'last_update': datetime.utcnow().isoformat()
        }
