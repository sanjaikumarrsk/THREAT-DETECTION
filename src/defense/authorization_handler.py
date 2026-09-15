"""
Authorization Handler - Manages user approval for defensive actions
"""
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from enum import Enum

logger = logging.getLogger(__name__)

class AuthorizationStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    TIMED_OUT = "timed_out"
    EXPIRED = "expired"

class AuthorizationHandler:
    """
    Manages user authorization workflow for defensive actions
    Ensures human authority over system responses
    Implements timeout-based fail-safe policies
    """
    
    def __init__(self):
        self.pending_approvals = {}
        self.approval_history = []
        self.security_policies = self._initialize_policies()
        logger.info("Authorization Handler initialized")
    
    def request_user_authorization(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create authorization request for user approval
        Returns alert information and control options
        """
        auth_request_id = f"auth_{action['action_id']}"
        
        timeout_seconds = action.get('timeout_seconds', 600)
        
        auth_request = {
            'auth_request_id': auth_request_id,
            'action_id': action['action_id'],
            'entity_id': action['entity_id'],
            'status': AuthorizationStatus.PENDING.value,
            'created_at': datetime.utcnow().isoformat(),
            'expires_at': (datetime.utcnow() + timedelta(seconds=timeout_seconds)).isoformat(),
            'timeout_seconds': timeout_seconds,
            
            # Alert Information
            'alert': {
                'title': f'Suspicious Activity Detected on {action["entity_id"]}',
                'description': 'Security system detected potentially malicious activity',
                'entity': action['entity_id'],
                'activity': action.get('recommended_action', 'Unknown'),
                'threat_assessment': action.get('threat_assessment', {}),
                'risk_level': action['threat_assessment'].get('risk_level'),
                'suspicion_score': action['threat_assessment'].get('suspicion_score')
            },
            
            # Detailed Information
            'details': {
                'recommended_action': action.get('recommended_action'),
                'rationale': action.get('rationale'),
                'operational_impact': action.get('operational_impact'),
                'reversible': action.get('reversible', True)
            },
            
            # User Controls
            'controls': {
                'stop_button': 'Cancel defense action and continue monitoring',
                'continue_button': 'Approve and execute defense action',
                'countdown': timeout_seconds
            },
            
            # Fail-Safe Information
            'fail_safe_info': {
                'timeout_behavior': self._get_fail_safe_description(action.get('threat_assessment', {}).get('risk_level')),
                'will_execute_if_no_response': True
            }
        }
        
        self.pending_approvals[auth_request_id] = auth_request
        
        logger.info(f"Authorization requested: {auth_request_id} for {action['entity_id']}")
        
        return auth_request
    
    def handle_user_response(self, auth_request_id: str, user_decision: str) -> Dict[str, Any]:
        """
        Handle user's response to authorization request
        
        user_decision: 'CONTINUE' or 'STOP'
        """
        if auth_request_id not in self.pending_approvals:
            logger.error(f"Authorization request not found: {auth_request_id}")
            return {'error': 'Request not found'}
        
        auth_request = self.pending_approvals[auth_request_id]
        
        # Check if request expired
        if datetime.fromisoformat(auth_request['expires_at']) < datetime.utcnow():
            auth_request['status'] = AuthorizationStatus.EXPIRED.value
            return {
                'auth_request_id': auth_request_id,
                'status': 'expired',
                'message': 'Authorization request has expired',
                'fail_safe_applied': True
            }
        
        if user_decision == 'CONTINUE':
            auth_request['status'] = AuthorizationStatus.APPROVED.value
            auth_request['approved_at'] = datetime.utcnow().isoformat()
            auth_request['user_decision'] = 'APPROVED'
            
            response = {
                'auth_request_id': auth_request_id,
                'status': 'approved',
                'action_id': auth_request['action_id'],
                'message': 'Defense action approved by user',
                'proceed_with_action': True
            }
            
            logger.info(f"Authorization approved: {auth_request_id}")
            
        elif user_decision == 'STOP':
            auth_request['status'] = AuthorizationStatus.REJECTED.value
            auth_request['rejected_at'] = datetime.utcnow().isoformat()
            auth_request['user_decision'] = 'REJECTED'
            
            response = {
                'auth_request_id': auth_request_id,
                'status': 'rejected',
                'action_id': auth_request['action_id'],
                'message': 'Defense action cancelled by user',
                'proceed_with_action': False
            }
            
            logger.info(f"Authorization rejected: {auth_request_id}")
        
        else:
            return {'error': 'Invalid user decision'}
        
        self.approval_history.append(auth_request)
        del self.pending_approvals[auth_request_id]
        
        return response
    
    def apply_fail_safe_policy(self, auth_request_id: str) -> Dict[str, Any]:
        """
        Apply fail-safe policy when user doesn't respond to authorization within timeout
        """
        if auth_request_id not in self.pending_approvals:
            return {'error': 'Request not found'}
        
        auth_request = self.pending_approvals[auth_request_id]
        action_id = auth_request['action_id']
        risk_level = auth_request['alert']['risk_level']
        
        # Determine fail-safe action based on risk level and policy
        fail_safe_action = self._get_fail_safe_action(risk_level)
        
        auth_request['status'] = AuthorizationStatus.TIMED_OUT.value
        auth_request['timed_out_at'] = datetime.utcnow().isoformat()
        auth_request['fail_safe_action_triggered'] = fail_safe_action
        
        response = {
            'auth_request_id': auth_request_id,
            'action_id': action_id,
            'status': 'timed_out',
            'message': f'User authorization timeout - applying fail-safe policy',
            'fail_safe_action': fail_safe_action,
            'execute_action': True,
            'reason': 'No user response within timeout period'
        }
        
        self.approval_history.append(auth_request)
        del self.pending_approvals[auth_request_id]
        
        logger.warning(f"Authorization timeout - fail-safe applied: {auth_request_id} → {fail_safe_action}")
        
        return response
    
    def _get_fail_safe_description(self, risk_level: str) -> str:
        """Get description of what happens if user doesn't respond"""
        descriptions = {
            'CRITICAL': 'If no response received, endpoint will be isolated from network',
            'HIGH': 'If no response received, suspicious process will be paused',
            'MEDIUM': 'If no response received, activity will be rate-limited',
            'LOW': 'If no response received, enhanced monitoring will continue',
            'MINIMAL': 'If no response received, monitoring will continue'
        }
        
        return descriptions.get(risk_level, 'If no response received, fail-safe policy will be applied')
    
    def _get_fail_safe_action(self, risk_level: str) -> str:
        """Determine fail-safe action based on risk level"""
        if risk_level == 'CRITICAL':
            return 'ISOLATE'
        elif risk_level == 'HIGH':
            return 'PAUSE'
        elif risk_level == 'MEDIUM':
            return 'RATE_LIMIT'
        else:
            return 'MONITOR'
    
    def get_pending_approvals(self, entity_id: str = None) -> List[Dict[str, Any]]:
        """Get list of pending authorization requests"""
        pending = []
        
        for auth_id, auth_request in self.pending_approvals.items():
            # Check if not expired
            if datetime.fromisoformat(auth_request['expires_at']) >= datetime.utcnow():
                if entity_id is None or auth_request.get('entity_id') == entity_id:
                    pending.append(auth_request)
        
        return pending
    
    def get_authorization_status(self, auth_request_id: str) -> Dict[str, Any]:
        """Get status of specific authorization request"""
        if auth_request_id in self.pending_approvals:
            auth_request = self.pending_approvals[auth_request_id]
            
            # Check expiration
            time_remaining = (datetime.fromisoformat(auth_request['expires_at']) - 
                            datetime.utcnow()).total_seconds()
            
            return {
                'auth_request_id': auth_request_id,
                'status': auth_request['status'],
                'time_remaining_seconds': max(int(time_remaining), 0),
                'expires_at': auth_request['expires_at'],
                'entity_id': auth_request['entity_id'],
                'risk_level': auth_request['alert']['risk_level']
            }
        
        # Check history
        for auth_request in self.approval_history:
            if auth_request.get('auth_request_id') == auth_request_id:
                return {
                    'auth_request_id': auth_request_id,
                    'status': auth_request['status'],
                    'resolved_at': auth_request.get('approved_at') or auth_request.get('rejected_at') or auth_request.get('timed_out_at'),
                    'entity_id': auth_request['entity_id'],
                    'decision': auth_request.get('user_decision', 'TIMEOUT')
                }
        
        return {'error': 'Authorization request not found'}
    
    def get_authorization_summary(self) -> Dict[str, Any]:
        """Get summary of authorization activities"""
        total_requests = len(self.approval_history) + len(self.pending_approvals)
        
        approved_count = sum(1 for a in self.approval_history if a['status'] == AuthorizationStatus.APPROVED.value)
        rejected_count = sum(1 for a in self.approval_history if a['status'] == AuthorizationStatus.REJECTED.value)
        timeout_count = sum(1 for a in self.approval_history if a['status'] == AuthorizationStatus.TIMED_OUT.value)
        
        return {
            'total_authorization_requests': total_requests,
            'pending_requests': len(self.pending_approvals),
            'completed_requests': len(self.approval_history),
            'approved': approved_count,
            'rejected': rejected_count,
            'timed_out_fail_safe_triggered': timeout_count,
            'approval_rate': f"{(approved_count / max(len(self.approval_history), 1) * 100):.1f}%" if self.approval_history else "N/A",
            'last_authorization': self.approval_history[-1]['approved_at'] if self.approval_history else None
        }
    
    def _initialize_policies(self) -> Dict[str, Dict]:
        """Initialize default authorization policies"""
        return {
            'default': {
                'name': 'Default Authorization Policy',
                'critical_timeout': 120,      # seconds
                'high_timeout': 300,
                'medium_timeout': 600,
                'low_timeout': 1200,
                'critical_fail_safe': 'ISOLATE',
                'high_fail_safe': 'PAUSE',
                'medium_fail_safe': 'RATE_LIMIT',
                'low_fail_safe': 'MONITOR',
                'require_human_approval': True,
                'audit_all_decisions': True
            }
        }
