"""
Response Engine - Executes defensive actions with policy control
Defense/Response Component
"""
import logging
from typing import Dict, List, Any
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)

class DefenseActionStatus(Enum):
    PENDING = "pending"
    AUTHORIZED = "authorized"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"

class ResponseEngine:
    """
    Executes defensive actions with policy control
    Never grants unrestricted AI authority - always requires authorization or timeout policy
    """
    
    def __init__(self):
        self.active_defenses = {}
        self.defense_history = []
        self.execution_log = []
        logger.info("Response Engine initialized")
    
    def prepare_defense_action(self, entity_id: str, risk_assessment: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepare defensive action based on risk assessment
        Returns proposed action awaiting user authorization
        """
        action_id = f"action_{entity_id}_{int(datetime.utcnow().timestamp())}"
        
        recommended_response = risk_assessment.get('recommended_response', {})
        
        action = {
            'action_id': action_id,
            'entity_id': entity_id,
            'timestamp': datetime.utcnow().isoformat(),
            'status': DefenseActionStatus.PENDING.value,
            'recommended_action': recommended_response.get('primary_action', 'MONITOR'),
            'threat_assessment': {
                'risk_level': risk_assessment.get('risk_level'),
                'suspicion_score': risk_assessment.get('suspicion_score'),
                'threat_classification': risk_assessment.get('threat_classification')
            },
            'rationale': recommended_response.get('description', ''),
            'operational_impact': recommended_response.get('operational_impact', 'Unknown'),
            'reversible': recommended_response.get('reversible', True),
            'requires_authorization': risk_assessment.get('requires_authorization', True),
            'timeout_seconds': risk_assessment.get('authorization_timeout_seconds', 600),
            'response_options': []
        }
        
        self.active_defenses[action_id] = action
        self.defense_history.append(action)
        
        logger.info(f"Defense action prepared: {action_id} for {entity_id}")
        
        return action
    
    def authorize_defense_action(self, action_id: str, user_decision: str) -> Dict[str, Any]:
        """
        Handle user authorization decision
        
        user_decision: 'CONTINUE' (execute), 'STOP' (cancel), or timeout (use fail-safe policy)
        """
        if action_id not in self.active_defenses:
            logger.error(f"Defense action not found: {action_id}")
            return {'error': 'Action not found'}
        
        action = self.active_defenses[action_id]
        
        if user_decision == 'CONTINUE':
            action['status'] = DefenseActionStatus.AUTHORIZED.value
            action['authorized_at'] = datetime.utcnow().isoformat()
            action['authorization_decision'] = 'APPROVED'
            
            # Execute the defense
            execution_result = self._execute_defense(action)
            action['status'] = DefenseActionStatus.EXECUTING.value
            
            logger.info(f"Defense action authorized: {action_id}")
            return execution_result
        
        elif user_decision == 'STOP':
            action['status'] = DefenseActionStatus.CANCELLED.value
            action['cancelled_at'] = datetime.utcnow().isoformat()
            action['authorization_decision'] = 'REJECTED'
            
            self.execution_log.append({
                'action_id': action_id,
                'event': 'DEFENSE_CANCELLED',
                'reason': 'User rejected defense action',
                'timestamp': datetime.utcnow().isoformat()
            })
            
            logger.info(f"Defense action cancelled: {action_id}")
            return {
                'status': 'cancelled',
                'action_id': action_id,
                'message': 'Defense action cancelled by user'
            }
        
        return {'error': 'Invalid authorization decision'}
    
    def apply_timeout_fail_safe(self, action_id: str, fail_safe_policy: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply fail-safe policy when user doesn't respond within timeout period
        Policy-driven response, not unrestricted AI action
        """
        if action_id not in self.active_defenses:
            return {'error': 'Action not found'}
        
        action = self.active_defenses[action_id]
        
        # Get configured fail-safe action from policy
        fail_safe_action = fail_safe_policy.get('fail_safe_action', 'PAUSE')
        
        action['status'] = DefenseActionStatus.TIMEOUT.value
        action['timeout_at'] = datetime.utcnow().isoformat()
        action['fail_safe_action_applied'] = fail_safe_action
        
        # Execute fail-safe response
        execution_result = self._execute_fail_safe(action, fail_safe_action)
        
        self.execution_log.append({
            'action_id': action_id,
            'event': 'TIMEOUT_FAIL_SAFE_APPLIED',
            'fail_safe_action': fail_safe_action,
            'timestamp': datetime.utcnow().isoformat()
        })
        
        logger.warning(f"Timeout fail-safe applied for {action_id}: {fail_safe_action}")
        
        return execution_result
    
    def _execute_defense(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the authorized defensive action"""
        action_type = action.get('recommended_action', 'MONITOR')
        entity_id = action.get('entity_id')
        
        execution_results = {
            'action_id': action['action_id'],
            'entity_id': entity_id,
            'action_type': action_type,
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'executing'
        }
        
        if action_type == 'MONITOR':
            result = self._execute_monitor(entity_id)
        elif action_type == 'RATE_LIMIT':
            result = self._execute_rate_limit(entity_id)
        elif action_type == 'PAUSE':
            result = self._execute_pause(entity_id)
        elif action_type == 'ISOLATE_ENDPOINT':
            result = self._execute_isolate(entity_id)
        elif action_type == 'TERMINATE':
            result = self._execute_terminate(entity_id)
        else:
            result = {'error': f'Unknown action type: {action_type}'}
        
        execution_results.update(result)
        
        action['execution_result'] = execution_results
        
        return execution_results
    
    def _execute_fail_safe(self, action: Dict[str, Any], fail_safe_action: str) -> Dict[str, Any]:
        """Execute fail-safe response when user times out"""
        entity_id = action.get('entity_id')
        
        execution_results = {
            'action_id': action['action_id'],
            'entity_id': entity_id,
            'fail_safe_action': fail_safe_action,
            'timestamp': datetime.utcnow().isoformat(),
            'reason': 'User authorization timeout'
        }
        
        if fail_safe_action == 'PAUSE':
            result = self._execute_pause(entity_id)
        elif fail_safe_action == 'ISOLATE':
            result = self._execute_isolate(entity_id)
        else:
            result = self._execute_monitor(entity_id)
        
        execution_results.update(result)
        return execution_results
    
    def _execute_monitor(self, entity_id: str) -> Dict[str, Any]:
        """Continue monitoring without intervention"""
        return {
            'action_executed': 'monitor',
            'details': f'Continuing enhanced monitoring for {entity_id}',
            'success': True
        }
    
    def _execute_rate_limit(self, entity_id: str) -> Dict[str, Any]:
        """Rate limit suspicious entity traffic"""
        return {
            'action_executed': 'rate_limit',
            'details': f'Rate limiting enabled for {entity_id}',
            'rate_limit_kbps': 1000,
            'success': True,
            'reversible': True
        }
    
    def _execute_pause(self, entity_id: str) -> Dict[str, Any]:
        """Pause suspicious process"""
        return {
            'action_executed': 'pause',
            'details': f'Process paused for {entity_id}',
            'process_id': 'PAUSED',
            'success': True,
            'reversible': True,
            'recovery_options': ['Resume', 'Terminate', 'Investigate']
        }
    
    def _execute_isolate(self, entity_id: str) -> Dict[str, Any]:
        """Isolate endpoint from network"""
        return {
            'action_executed': 'isolate',
            'details': f'Endpoint {entity_id} isolated from network',
            'network_access': 'disabled',
            'success': True,
            'reversible': True,
            'recovery_options': ['Reconnect to Network', 'Quarantine for Investigation']
        }
    
    def _execute_terminate(self, entity_id: str) -> Dict[str, Any]:
        """Terminate suspicious connection/process"""
        return {
            'action_executed': 'terminate',
            'details': f'Connection terminated for {entity_id}',
            'success': True,
            'reversible': False,
            'notes': 'Irreversible action - evidence preserved'
        }
    
    def get_active_defenses(self, entity_id: str = None) -> List[Dict[str, Any]]:
        """Get list of active defense actions"""
        active = []
        
        for action_id, action in self.active_defenses.items():
            if entity_id is None or action.get('entity_id') == entity_id:
                if action['status'] in [DefenseActionStatus.PENDING.value, 
                                       DefenseActionStatus.AUTHORIZED.value,
                                       DefenseActionStatus.EXECUTING.value]:
                    active.append(action)
        
        return active
    
    def get_defense_status(self, action_id: str) -> Dict[str, Any]:
        """Get status of specific defense action"""
        if action_id in self.active_defenses:
            return self.active_defenses[action_id]
        
        return {'error': 'Action not found'}
    
    def get_defense_summary(self) -> Dict[str, Any]:
        """Get summary of all defense activities"""
        return {
            'total_actions': len(self.defense_history),
            'active_defenses': len(self.get_active_defenses()),
            'completed': sum(1 for a in self.defense_history if a['status'] == DefenseActionStatus.COMPLETED.value),
            'cancelled': sum(1 for a in self.defense_history if a['status'] == DefenseActionStatus.CANCELLED.value),
            'timeout_triggered': sum(1 for a in self.defense_history if a['status'] == DefenseActionStatus.TIMEOUT.value),
            'last_action': self.defense_history[-1]['timestamp'] if self.defense_history else None
        }
