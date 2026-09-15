"""
API Routes for the dashboard and security operations
"""
import logging
from flask_restful import Resource, reqparse
from flask import current_app, request, jsonify
from datetime import datetime

logger = logging.getLogger(__name__)

class AlertResource(Resource):
    """Handle alert management"""
    
    def get(self, alert_id=None):
        """Get alerts"""
        if not alert_id and getattr(current_app, 'demo_service', None):
            alerts = current_app.demo_service.alerts()
            parser = reqparse.RequestParser()
            parser.add_argument('entity_id', type=str, location='args')
            parser.add_argument('hours', type=int, default=24, location='args')
            args = parser.parse_args()
            if args.entity_id:
                alerts = [alert for alert in alerts if alert.get('entity_id') == args.entity_id]
            return {'alerts': alerts, 'total': len(alerts), 'demo': True}, 200
        if alert_id:
            # Get specific alert
            alerts = current_app.data_vault.retrieve_telemetry(alert_id, authenticated=True)
            return {'alert': alerts}, 200
        else:
            # Get recent alerts
            parser = reqparse.RequestParser()
            parser.add_argument('entity_id', type=str, location='args')
            parser.add_argument('hours', type=int, default=24, location='args')
            args = parser.parse_args()
            
            alerts = current_app.data_vault.get_alerts(
                entity_id=args.entity_id,
                hours=args.hours
            )
            return {'alerts': alerts, 'total': len(alerts)}, 200
    
    def post(self):
        """Create new alert"""
        data = request.get_json()
        
        alert_id = current_app.data_vault.store_alert(data)
        
        return {
            'status': 'success',
            'alert_id': alert_id,
            'timestamp': datetime.utcnow().isoformat()
        }, 201


class DashboardResource(Resource):
    """Dashboard summary and visualization data"""
    
    def get(self):
        """Get dashboard data"""
        if getattr(current_app, 'demo_service', None):
            return current_app.demo_service.dashboard(), 200
        
        # Get system status
        collector_status = current_app.data_collector.get_collection_status()
        vault_status = current_app.data_vault.get_vault_status()
        defense_summary = current_app.response_engine.get_defense_summary()
        auth_summary = current_app.authorization_handler.get_authorization_summary()
        verification_summary = current_app.verification_engine.get_effectiveness_summary()
        risk_summary = current_app.risk_engine.get_risk_recommendations()
        
        # Get recent alerts
        recent_alerts = current_app.data_vault.get_alerts(hours=1)
        active_defenses = current_app.response_engine.get_active_defenses()
        pending_approvals = current_app.authorization_handler.get_pending_approvals()
        
        dashboard_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'system_status': {
                'data_collection': collector_status,
                'data_vault': vault_status,
                'certification_status': {
                    'certification_ready': True,
                    'certified': False,
                    'roadmap': ['Security Testing', 'Vulnerability Assessment', 'Independent Audit']
                }
            },
            'security_posture': {
                'active_monitoring': collector_status.get('is_collecting', False),
                'entities_monitored': len(current_app.data_vault.baselines),
                'recent_alerts': len(recent_alerts),
                'active_defenses': len(active_defenses),
                'pending_authorizations': len(pending_approvals)
            },
            'threat_summary': risk_summary,
            'defense_summary': defense_summary,
            'authorization_summary': auth_summary,
            'verification_summary': verification_summary,
            'recent_alerts': recent_alerts[-10:] if recent_alerts else [],
            'active_defenses': active_defenses[:5] if active_defenses else [],
            'pending_approvals': pending_approvals[:5] if pending_approvals else []
        }
        
        return dashboard_data, 200


class DefenseResource(Resource):
    """Handle defense action management"""
    
    def get(self, defense_id=None):
        """Get defense action status"""
        if getattr(current_app, 'demo_service', None):
            defenses = current_app.demo_service.dashboard().get('active_defenses', [])
            if defense_id:
                defense = next((item for item in defenses if item.get('defense_id') == defense_id), None)
                return {'defense': defense or {'error': 'Action not found'}, 'demo': True}, 200
            return {'defenses': defenses, 'total': len(defenses), 'demo': True}, 200
        if defense_id:
            status = current_app.response_engine.get_defense_status(defense_id)
            return {'defense': status}, 200
        else:
            # Get all defense actions
            all_defenses = current_app.response_engine.get_active_defenses()
            return {'defenses': all_defenses, 'total': len(all_defenses)}, 200
    
    def post(self):
        """Initiate new defense action"""
        data = request.get_json()
        
        # This would be called by the risk engine
        # For now, just acknowledge
        return {
            'status': 'defense_initiated',
            'timestamp': datetime.utcnow().isoformat()
        }, 201
    
    def put(self, defense_id):
        """Update defense action (e.g., user authorization)"""
        data = request.get_json()
        decision = data.get('decision')  # 'CONTINUE' or 'STOP'

        if getattr(current_app, 'demo_service', None) and defense_id == 'DEF-007':
            result = current_app.demo_service.authorize('INC-007', decision or 'STOP')
            return result, 200
        
        result = current_app.response_engine.authorize_defense_action(defense_id, decision)
        
        return result, 200


class IncidentResource(Resource):
    """Handle incident/attack story management"""
    
    def get(self, incident_id=None):
        """Get incident details"""
        if getattr(current_app, 'demo_service', None):
            if incident_id:
                incident = current_app.demo_service.incident(incident_id)
                return {'incident': incident, 'demo': True}, 200 if incident else 404
            incidents = current_app.demo_service.incidents()
            return {'incidents': incidents, 'total': len(incidents), 'demo': True}, 200
        if incident_id:
            incident = current_app.incident_engine.incidents.get(incident_id)
            return {'incident': incident}, 200 if incident else 404
        else:
            # Get all incidents
            incidents = list(current_app.incident_engine.incidents.values())
            return {'incidents': incidents, 'total': len(incidents)}, 200
    
    def post(self):
        """Create incident from correlating alerts"""
        data = request.get_json()
        alerts = data.get('alerts', [])
        
        incidents = current_app.incident_engine.correlate_alerts(alerts)
        
        return incidents, 201


class VerificationResource(Resource):
    """Handle post-defense verification"""
    
    def get(self, defense_id):
        """Get verification results for a defense"""
        if getattr(current_app, 'demo_service', None):
            incident = current_app.demo_service.incident('INC-007') if defense_id == 'DEF-007' else None
            latest = incident.get('verification') if incident else None
            return {'defense_id': defense_id, 'verifications': [latest] if latest else [], 'latest': latest, 'demo': True}, 200
        # Get verification history for this defense
        history = current_app.verification_engine.get_verification_history()
        defense_verifications = [v for v in history if v.get('defense_id') == defense_id]
        
        return {
            'defense_id': defense_id,
            'verifications': defense_verifications,
            'latest': defense_verifications[-1] if defense_verifications else None
        }, 200
    
    def post(self, defense_id):
        """Record post-defense verification results"""
        if getattr(current_app, 'demo_service', None) and defense_id == 'DEF-007':
            return current_app.demo_service.verify('INC-007'), 201
        data = request.get_json()
        
        entity_id = data.get('entity_id')
        pre_metrics = data.get('pre_defense_metrics', {})
        post_metrics = data.get('post_defense_metrics', {})
        
        verification_result = current_app.verification_engine.monitor_post_defense(
            entity_id=entity_id,
            defense_id=defense_id,
            pre_defense_metrics=pre_metrics,
            post_defense_metrics=post_metrics
        )
        
        return verification_result, 201


class EntityBehaviorResource(Resource):
    """Handle entity behavioral baseline management"""
    
    def get(self, entity_id):
        """Get behavioral baseline and status for entity"""
        baseline = current_app.data_vault.get_baseline(entity_id)
        entity_status = current_app.anomaly_detector.get_entity_status(entity_id)
        recent_telemetry = current_app.data_vault.get_telemetry_for_entity(entity_id, hours=1)
        
        return {
            'entity_id': entity_id,
            'behavioral_baseline': baseline,
            'entity_status': entity_status,
            'recent_telemetry_count': len(recent_telemetry)
        }, 200
    
    def post(self, entity_id):
        """Establish or update baseline for entity"""
        data = request.get_json()
        baseline_metrics = data.get('baseline_metrics', {})
        
        current_app.anomaly_detector.establish_baseline(entity_id, baseline_metrics)
        current_app.data_vault.store_baseline(entity_id, baseline_metrics)
        
        return {
            'status': 'baseline_established',
            'entity_id': entity_id,
            'timestamp': datetime.utcnow().isoformat()
        }, 201


class AuthorizationResource(Resource):
    """Handle user authorization requests"""
    
    def get(self, auth_request_id=None):
        """Get authorization request status"""
        if auth_request_id:
            status = current_app.authorization_handler.get_authorization_status(auth_request_id)
            return status, 200
        else:
            pending = current_app.authorization_handler.get_pending_approvals()
            return {'pending_approvals': pending, 'total': len(pending)}, 200
    
    def post(self, auth_request_id):
        """Submit user decision on authorization request"""
        data = request.get_json()
        user_decision = data.get('decision')  # 'CONTINUE' or 'STOP'
        
        result = current_app.authorization_handler.handle_user_response(
            auth_request_id, user_decision
        )
        
        return result, 200
