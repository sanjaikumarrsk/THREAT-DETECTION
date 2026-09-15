"""
Main application entry point for Cyber Threat Defense System
"""
import os
import logging
from flask import Flask, request
from flask_cors import CORS
from flask_restful import Api
import sys

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.core.collector import DataCollector
from src.core.data_vault import DataVault
from src.models.threat_detector import ThreatDetector
from src.models.anomaly_detector import AnomalyDetector
from src.core.threat_fusion import ThreatFusion
from src.core.risk_engine import RiskEngine, IncidentEngine
from src.defense.response_engine import ResponseEngine
from src.defense.authorization_handler import AuthorizationHandler
from src.core.verification_engine import VerificationEngine
from src.demo_service import DemoService

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def create_app():
    """Create and configure Flask application"""
    app = Flask(__name__)
    CORS(app)
    
    # Load configuration
    app.config.from_object('config.settings')
    
    # Initialize API
    api = Api(app)
    
    # Initialize core systems
    try:
        # Data collection and storage
        data_collector = DataCollector()
        data_vault = DataVault()
        
        # AI Models
        threat_detector = ThreatDetector()
        anomaly_detector = AnomalyDetector()
        
        # Processing pipeline
        threat_fusion = ThreatFusion()
        risk_engine = RiskEngine()
        incident_engine = IncidentEngine()
        
        # Defense and response
        response_engine = ResponseEngine()
        authorization_handler = AuthorizationHandler()
        
        # Verification
        verification_engine = VerificationEngine()
        demo_service = DemoService()
        
        # Store in app context
        app.data_collector = data_collector
        app.data_vault = data_vault
        app.threat_detector = threat_detector
        app.anomaly_detector = anomaly_detector
        app.threat_fusion = threat_fusion
        app.risk_engine = risk_engine
        app.incident_engine = incident_engine
        app.response_engine = response_engine
        app.authorization_handler = authorization_handler
        app.verification_engine = verification_engine
        app.demo_service = demo_service
        
        logger.info("All core systems initialized successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize core systems: {e}")
        raise
    
    # Register API routes
    register_routes(api, app)
    register_demo_routes(app)
    
    @app.route('/health')
    def health():
        return {'status': 'healthy'}, 200
    
    return app

def register_routes(api, app):
    """Register API routes"""
    from src.ui.routes import (
        AlertResource, DashboardResource, DefenseResource,
        IncidentResource, VerificationResource, EntityBehaviorResource,
        AuthorizationResource
    )
    
    api.add_resource(AlertResource, '/api/alerts', '/api/alerts/<string:alert_id>')
    api.add_resource(DashboardResource, '/api/dashboard')
    api.add_resource(DefenseResource, '/api/defense', '/api/defense/<string:defense_id>')
    api.add_resource(IncidentResource, '/api/incidents', '/api/incidents/<string:incident_id>')
    api.add_resource(VerificationResource, '/api/verification/<string:defense_id>')
    api.add_resource(EntityBehaviorResource, '/api/entities/<string:entity_id>/behavior')
    api.add_resource(AuthorizationResource, '/api/authorization', '/api/authorization/<string:auth_request_id>')


def register_demo_routes(app):
    """Expose the seeded prototype workflow without replacing core APIs."""

    @app.route('/api/traffic/live')
    def demo_live_traffic():
        return app.demo_service.traffic(), 200

    @app.route('/api/timeline')
    def demo_timeline():
        return {'timeline': app.demo_service.timeline(), 'demo': True}, 200

    @app.route('/api/audit')
    @app.route('/api/audit-log')
    def demo_audit():
        return {'events': app.demo_service.audit(), 'demo': True}, 200

    @app.route('/api/models/known-pattern')
    def demo_known_pattern():
        return app.demo_service.known_pattern(), 200

    @app.route('/api/models/behavior')
    def demo_behavior():
        return app.demo_service.behavior(), 200

    @app.route('/api/risk')
    def demo_risk():
        return app.demo_service.risk(), 200

    @app.route('/api/policy')
    def demo_policy():
        return {'policy': app.demo_service.policy(), 'demo': True}, 200

    @app.route('/api/demo/state')
    def demo_state():
        return app.demo_service.demo_state(), 200

    @app.post('/api/demo/start')
    def demo_start():
        return app.demo_service.start_demo(), 200

    @app.post('/api/demo/reset')
    def demo_reset():
        return app.demo_service.reset_demo(), 200

    @app.post('/api/incidents/<string:incident_id>/authorize')
    def demo_authorize(incident_id):
        data = request.get_json(silent=True) or {}
        return app.demo_service.authorize(incident_id, data.get('decision', 'STOP')), 200

    @app.post('/api/incidents/<string:incident_id>/stop')
    def demo_stop(incident_id):
        return app.demo_service.stop_incident(incident_id), 200

    @app.post('/api/incidents/<string:incident_id>/continue')
    def demo_continue(incident_id):
        return app.demo_service.continue_incident(incident_id), 200

    @app.post('/api/incidents/<string:incident_id>/verify')
    def demo_verify(incident_id):
        return app.demo_service.verify(incident_id), 201

if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5000, debug=False)
