import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  Activity,
  ArrowDownRight,
  ArrowUpRight,
  Bell,
  Check,
  CheckCircle2,
  ChevronRight,
  CircleAlert,
  Clock3,
  Command,
  Copy,
  ExternalLink,
  Eye,
  FileCheck2,
  Fingerprint,
  Gauge,
  Globe2,
  Layers3,
  LockKeyhole,
  Menu,
  MoreHorizontal,
  Network,
  Radio,
  RefreshCw,
  Search,
  Server,
  ShieldCheck,
  ShieldEllipsis,
  Sparkles,
  Target,
  X,
  Zap,
} from 'lucide-react';
import './styles.css';

const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000';
const DEMO_SESSION_KEY = 'aegisflow-demo-session';
const DEMO_LABEL = 'SIMULATED PROTOTYPE DATA';

const images = {
  hero: 'https://images.unsplash.com/photo-1485827404703-89b55fcc595e?auto=format&fit=crop&w=1800&q=88',
  network: 'https://images.unsplash.com/photo-1558494949-ef010cbdcc31?auto=format&fit=crop&w=1200&q=84',
  operations: 'https://images.unsplash.com/photo-1550751827-4bd374c3f58b?auto=format&fit=crop&w=1100&q=84',
  infrastructure: 'https://images.unsplash.com/photo-1518770660439-4636190af475?auto=format&fit=crop&w=1400&q=84',
};

const emptyMessage = 'Waiting for live telemetry';

function formatDate(value) {
  if (!value) return 'Awaiting timestamp';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat('en', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }).format(date);
}

function formatMetric(value, suffix = '') {
  if (value === undefined || value === null || value === '') return '—';
  return `${value}${suffix}`;
}

function getRiskLevel(item) {
  const raw = item?.risk_level || item?.risk || item?.severity || '';
  return String(raw).toLowerCase() || 'unknown';
}

function riskClass(level) {
  return ['low', 'medium', 'high', 'critical'].includes(level) ? level : 'unknown';
}

function attackLabel(value) {
  if (!value) return 'Unclassified';
  return String(value).replace(/_/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function getArray(payload, keys = []) {
  if (Array.isArray(payload)) return payload;
  for (const key of keys) {
    if (Array.isArray(payload?.[key])) return payload[key];
  }
  return [];
}

function normalizeAlert(item) {
  const data = item?.data && typeof item.data === 'object' ? item.data : item || {};
  const id = data.incident_id || data.id || item?.id;
  return {
    ...data,
    id,
    incident_id: data.incident_id || (id ? `alert-${id}` : undefined),
    entity_id: data.entity_id || item?.entity_id,
    created_at: data.created_at || data.timestamp || item?.timestamp,
    attack_type: data.attack_type || data.threat_classification || data.classification,
    risk_level: data.risk_level || data.severity,
    risk_score: data.risk_score ?? data.suspicion_score,
    status: data.status || 'alert',
  };
}

function normalizePendingApproval(item) {
  const assessment = item?.alert?.threat_assessment || {};
  return {
    ...item,
    id: item?.action_id || item?.auth_request_id,
    incident_id: item?.action_id || item?.auth_request_id,
    defense_id: item?.action_id,
    entity_id: item?.entity_id || item?.alert?.entity,
    attack_type: item?.alert?.activity || 'Authorization required',
    risk_level: item?.alert?.risk_level || assessment.risk_level,
    risk_score: assessment.suspicion_score,
    recommended_action: item?.details?.recommended_action,
    state: item?.authorization?.status === 'PENDING' || item?.status === 'PENDING' ? 'pending' : item?.state || item?.status,
    top_factors: item?.details?.rationale ? [item.details.rationale] : [],
    assessment: item?.details?.rationale || 'Low known-pattern resemblance plus high behavioral deviation',
    model_1: { similarity: item?.model_1?.similarity ?? 12, attack_type: item?.model_1?.status || 'LOW known-pattern resemblance' },
    model_2: { anomaly_score: item?.model_2?.deviation ?? 94, status: item?.model_2?.status || 'BEHAVIOR DEVIATION DETECTED' },
    fusion: { risk_score: item?.risk_score ?? 88, risk_level: item?.risk_level || 'HIGH', assessment: item?.assessment || 'Low known-pattern resemblance plus high behavioral deviation' },
  };
}

function normalizeIncident(item) {
  const known = item?.known_pattern || {};
  const behavior = item?.behavior_model || {};
  const factors = item?.explanation || item?.deviation_factors || [];
  return {
    ...item,
    attack_type: item?.attack_type || item?.classification || known.classification,
    risk_level: item?.risk_level || item?.risk?.risk_level || item?.severity,
    risk_score: item?.risk_score ?? item?.risk?.risk_score,
    recommended_action: item?.recommended_action || item?.recommendation?.action,
    defense_id: item?.defense_id || item?.defense?.defense_id,
    top_factors: factors.map((factor) => factor.factor || factor.name || factor.explanation || factor),
    model_1: { attack_type: known.status || (known.similarity <= 20 ? 'LOW known-pattern resemblance' : known.classification || item?.attack_type), confidence: item?.confidence_percent ?? item?.confidence, similarity: known.similarity ?? item?.known_pattern_similarity, status: known.status },
    model_2: { anomaly_score: behavior.anomaly_score ?? item?.behavioral_deviation, score: behavior.anomaly_score ?? item?.behavioral_deviation, status: behavior.status || behavior.severity },
    fusion: { risk_score: item?.risk_score ?? item?.risk?.risk_score, risk_level: item?.risk_level || item?.risk?.risk_level, top_factors: factors },
    factors,
  };
}

function simulationUiState(mode, incident) {
  if (incident?.authorization?.status === 'TIMED_OUT') return 'timed_out';
  if (mode === 'defending') return 'executing';
  if (mode === 'verifying') return 'verification';
  if (mode === 'resolved') return 'resolved';
  if (mode === 'stopped') return 'cancelled';
  return 'pending';
}

function canVerifyAuditChain(entries) {
  if (entries.length < 2) return false;
  return entries.every((entry, index) => {
    const hash = entry.hash || entry.hash_value;
    const previous = entry.previous_hash || entry.prev_hash || entry.previous;
    return Boolean(hash && (index === 0 || previous));
  });
}

function DataStatus({ children = emptyMessage, compact = false }) {
  return (
    <div className={`data-status ${compact ? 'data-status--compact' : ''}`}>
      <span className="data-status__mark" />
      <span>{children}</span>
    </div>
  );
}

function SectionKicker({ eyebrow, title, description, action }) {
  return (
    <div className="section-kicker">
      <div>
        <div className="eyebrow"><span className="eyebrow__line" />{eyebrow}</div>
        <h2>{title}</h2>
      </div>
      {description && <p>{description}</p>}
      {action}
    </div>
  );
}

function IconButton({ label, children, onClick }) {
  return <button type="button" className="icon-button" aria-label={label} title={label} onClick={onClick}>{children}</button>;
}

function StatusMarker({ label, tone = 'neutral' }) {
  return <span className={`status-marker status-marker--${tone}`}><span />{label}</span>;
}

function Hero() {
  return (
    <section className="hero" id="overview">
      <div className="hero__copy">
        <div className="eyebrow"><span className="eyebrow__line" />Cyber defense / real-time intelligence</div>
        <h1>See the threat.<br /><em>Control</em> the response.</h1>
        <p className="hero__lede">A security command center that combines known-attack detection, behavioral intelligence, explainable risk, and verified response.</p>
        <div className="hero__actions">
          <a className="button button--primary" href="#incidents">Explore active threats <ChevronRight size={16} /></a>
          <a className="button button--text" href="#timeline">View attack timeline <ArrowDownRight size={16} /></a>
        </div>
        <div className="hero__proof">
          <div><span className="proof__value">SEE</span><span className="proof__label">detect</span></div>
          <div><span className="proof__value">DECIDE</span><span className="proof__label">assess</span></div>
          <div><span className="proof__value">PROVE</span><span className="proof__label">verify</span></div>
        </div>
      </div>
      <div className="hero__visual">
        <div className="hero__visual-grid" />
        <img src={images.hero} alt="Sculptural humanoid robot representing an AI security analyst" />
        <div className="hero__visual-shade" />
        <div className="annotation annotation--top"><span className="annotation__pin" />Threat fusion <strong>active</strong></div>
        <div className="annotation annotation--left"><span className="annotation__pin annotation__pin--orange" />Entity <strong>SRV-042</strong></div>
        <div className="annotation annotation--right"><span className="annotation__pin annotation__pin--green" />Verification <strong>ready</strong></div>
        <div className="hero__visual-index">01 <span>/</span> 04</div>
        <div className="hero__visual-caption">Autonomous defense<br /><span>human-authorized response</span></div>
      </div>
    </section>
  );
}

function MetricBand({ metrics }) {
  const data = metrics || {};
  const distribution = data.risk_distribution || data.distribution || {};
  const total = data.total_incidents ?? data.total ?? data.incidents_count;
  return (
    <section className="metric-band" aria-label="Operational metrics">
      <div className="metric-lead">
        <div className="eyebrow"><span className="eyebrow__line" />Command pulse</div>
        <p>Measured from the live defense plane.</p>
      </div>
      <div className="metric metric--hero">
        <span className="metric__label">Mean time to detect</span>
        <strong>{formatMetric(data.mttd, data.mttd !== undefined ? ' ms' : '')}</strong>
        <span className="metric__foot"><Clock3 size={13} /> simulated demo metric</span>
      </div>
      <div className="metric metric--hero">
        <span className="metric__label">Mean time to respond</span>
        <strong>{formatMetric(data.mttr, data.mttr !== undefined ? ' min' : '')}</strong>
        <span className="metric__foot"><Zap size={13} /> simulated demo metric</span>
      </div>
      <div className="metric metric--distribution">
        <div className="metric__topline"><span className="metric__label">Risk distribution</span><span className="metric__total">{formatMetric(total)} total</span></div>
        <div className="risk-bars">
          {['critical', 'high', 'medium', 'low'].map((level) => <div className="risk-bar" key={level}><span className={`risk-bar__value risk-bar__value--${level}`}>{distribution[level] ?? '—'}</span><span className="risk-bar__label">{level}</span></div>)}
        </div>
      </div>
    </section>
  );
}

function TrafficChart({ traffic }) {
  const values = traffic.map((item) => Number(item.requests_per_min ?? item.requests ?? item.rpm)).filter(Number.isFinite);
  const max = Math.max(...values, 1);
  return (
    <div className="traffic-chart">
      <div className="traffic-chart__grid" />
      {values.length ? <div className="traffic-chart__bars">{values.slice(-18).map((value, index) => <span key={`${value}-${index}`} style={{ height: `${Math.max(8, (value / max) * 100)}%` }} />)}</div> : <DataStatus />}
      <div className="traffic-chart__axis"><span>− 60 min</span><span>live</span></div>
    </div>
  );
}

function TrafficPanel({ traffic }) {
  const latest = traffic[traffic.length - 1];
  return (
    <section className="panel traffic-panel" id="traffic">
      <div className="panel__head">
        <div><div className="eyebrow"><span className="eyebrow__line" />01 / live traffic</div><h3>Network activity</h3></div>
        <StatusMarker label={traffic.length ? 'streaming' : 'waiting'} tone={traffic.length ? 'green' : 'neutral'} />
      </div>
      <div className="traffic-panel__summary">
        <div><span>Observed entity</span><strong>{latest?.entity_id || '—'}</strong></div>
        <div><span>Requests / min</span><strong>{latest?.requests_per_min ?? latest?.requests ?? '—'}</strong></div>
        <div><span>Failed connections</span><strong>{latest?.failed_connections ?? '—'}</strong></div>
      </div>
      <TrafficChart traffic={traffic} />
      <div className="traffic-panel__foot"><span>Outbound / {latest?.outbound_mb_per_min ?? latest?.outbound_mb_per_minute ?? '—'} MB/min · Destinations / {latest?.unique_destinations ?? '—'}</span><span>Failed / {latest?.failed_connections ?? '—'} · {latest?.stage || 'NORMAL'} · {formatDate(latest?.timestamp || latest?.created_at)}</span></div>
    </section>
  );
}

function FusionPanel({ traffic }) {
  return (
    <section className="fusion-panel">
      <div className="fusion-panel__image"><img src={images.operations} alt="Security operations room" /><div className="fusion-panel__wash" /><span className="image-stamp">AEGISFLOW / 02</span></div>
      <div className="fusion-panel__body">
        <div className="eyebrow"><span className="eyebrow__line" />02 / intelligence</div>
        <h3>Threat<br /><em>fusion</em></h3>
        <p>Two independent signals, one explainable decision. Known attack patterns meet live behavioral deviation.</p>
        <div className="fusion-panel__signals"><div><span className="signal-dot signal-dot--cobalt" /><span>Model 01 / classifier</span></div><div><span className="signal-dot signal-dot--orange" /><span>Model 02 / behavior</span></div><div><span className="signal-dot signal-dot--sage" /><span>Fusion / {traffic.length ? 'receiving' : 'awaiting data'}</span></div></div>
        <a className="inline-link" href="#incidents">Open intelligence view <ArrowUpRight size={15} /></a>
      </div>
    </section>
  );
}

function SignalSection({ traffic }) {
  return (
    <section className="section signal-section">
      <SectionKicker eyebrow="Live signal / observe" title={<>The system is always<br /><em>listening.</em></>} description="A clear view of the network surface, without losing the human story behind every event." />
      <div className="signal-grid"><TrafficPanel traffic={traffic} /><FusionPanel traffic={traffic} /></div>
    </section>
  );
}

function IncidentRow({ incident, onOpen }) {
  const level = getRiskLevel(incident);
  return (
    <button className={`incident-row incident-row--${riskClass(level)}`} type="button" onClick={() => onOpen(incident)}>
      <span className="incident-row__rail" />
      <span className="incident-row__id">{incident.incident_id || incident.id || '—'}</span>
      <span className="incident-row__entity"><span>{incident.entity_id || 'Unknown entity'}</span><small>{formatDate(incident.created_at || incident.timestamp)}</small></span>
      <span className="incident-row__attack"><small>classification</small><strong>{attackLabel(incident.attack_type || incident.classification)}</strong></span>
      <span className="incident-row__risk"><small>risk</small><strong>{incident.risk_score ?? '—'} <em>{level}</em></strong></span>
      <span className="incident-row__state"><span className="state-dot" />{incident.state || incident.status || 'unresolved'}</span>
      <ChevronRight size={17} className="incident-row__arrow" />
    </button>
  );
}

function IncidentsSection({ incidents, onOpen }) {
  return (
    <section className="section incidents-section" id="incidents">
      <SectionKicker eyebrow="Active incidents / decide" title={<>Attention, <em>with context.</em></>} description="Every alert carries its evidence, recommended action, and a human decision point." action={<a className="button button--outline" href="#audit">View audit trail <ExternalLink size={14} /></a>} />
      <div className="incidents-shell">
        <div className="incidents-shell__head"><span>{incidents.length ? `${incidents.length} active records` : 'Active incident ledger'}</span><span>updated from backend</span></div>
        {incidents.length ? <div className="incident-list">{incidents.map((incident, index) => <IncidentRow key={incident.incident_id || incident.id || index} incident={incident} onOpen={onOpen} />)}</div> : <div className="empty-ledger"><div className="empty-ledger__symbol"><Radio size={22} /></div><div><strong>{emptyMessage}</strong><p>When a new incident arrives, its evidence and decision state will appear here.</p></div><span className="empty-ledger__line" /></div>}
      </div>
    </section>
  );
}

function Timeline({ incidents }) {
  const ordered = [...incidents].sort((a, b) => new Date(a.created_at || a.timestamp || 0) - new Date(b.created_at || b.timestamp || 0));
  const grouped = ordered.reduce((result, incident) => {
    const entity = incident.entity_id || 'Unknown entity';
    if (!result[entity]) result[entity] = [];
    result[entity].push(incident);
    return result;
  }, {});
  return (
    <section className="section timeline-section" id="timeline">
      <SectionKicker eyebrow="Attack timeline / understand" title={<>Follow the <em>story.</em></>} description="Relationships are only drawn when the incident records share an entity and a recorded sequence." />
      <div className="timeline-layout">
        <div className="timeline-intro"><span className="timeline-intro__number">03</span><h3>From signal<br />to <em>proof.</em></h3><p>Investigate the progression of an event, then see where response changed its trajectory.</p><span className="timeline-intro__rule" /></div>
        <div className="timeline-content">
          {Object.keys(grouped).length ? Object.entries(grouped).map(([entity, rows]) => <div className="timeline-group" key={entity}><div className="timeline-group__head"><span className="timeline-group__entity">{entity}</span><span>{rows.length} linked {rows.length === 1 ? 'event' : 'events'}</span></div><div className="timeline-steps">{rows.map((item, index) => <div className="timeline-step" key={item.incident_id || item.id || index}><span className="timeline-step__dot" /><span className="timeline-step__label">{attackLabel(item.attack_type || item.classification)}</span><span className="timeline-step__date">{formatDate(item.created_at || item.timestamp)}</span>{index < rows.length - 1 && <span className="timeline-step__connector" />}</div>)}</div></div>) : <div className="timeline-empty"><Layers3 size={21} /><div><strong>Timeline will take shape from linked records.</strong><span>{emptyMessage}</span></div></div>}
        </div>
      </div>
    </section>
  );
}

function Explainer({ detail }) {
  const model1 = detail?.model_1 || detail?.classifier || {};
  const model2 = detail?.model_2 || detail?.behavior || {};
  const fusion = detail?.fusion || {};
  const factors = detail?.deviation_factors || detail?.factors || fusion.top_factors || [];
  const normalizedFactors = Array.isArray(factors) ? factors : Object.entries(factors).map(([name, contribution]) => ({ name, contribution }));
  return (
    <div className="explainer">
      <div className="explainer__head"><div><div className="eyebrow"><span className="eyebrow__line" />Why this incident matters</div><h3>Explainable risk <em>assessment.</em></h3></div><ShieldEllipsis size={29} /></div>
      <div className="model-grid">
        <div className="model-card"><span className="model-card__num">01</span><span className="model-card__label">Attack classifier</span><strong>{attackLabel(model1.attack_type || model1.label || detail?.attack_type)}</strong><span className="model-card__sub">confidence / {model1.confidence ?? '—'}</span></div>
        <div className="model-card"><span className="model-card__num">02</span><span className="model-card__label">Behavior model</span><strong>{model2.anomaly_score ?? model2.score ?? '—'}</strong><span className="model-card__sub">anomaly score</span></div>
        <div className="model-card model-card--fusion"><span className="model-card__num">03</span><span className="model-card__label">Fusion decision</span><strong>{fusion.risk_score ?? detail?.risk_score ?? '—'}</strong><span className="model-card__sub">{attackLabel(fusion.risk_level || detail?.risk_level)} risk</span></div>
      </div>
      <div className="factors"><span className="factors__label">Deviation factors</span>{normalizedFactors.length ? normalizedFactors.slice(0, 5).map((factor, index) => <div className="factor" key={factor.name || factor.factor || index}><div className="factor__meta"><span>{factor.name || factor.factor || factor.label}</span><strong>{factor.contribution ?? factor.value ?? '—'}</strong></div><div className="factor__track"><span style={{ width: `${Math.min(100, Math.max(8, Number(factor.contribution) || 8))}%` }} /></div></div>) : <DataStatus compact />}</div>
    </div>
  );
}

function DetailPanel({ incident, detail, onClose }) {
  const target = detail || incident;
  if (!target) return null;
  const level = getRiskLevel(target);
  return (
    <aside className="detail-drawer" aria-label="Incident detail">
      <div className="detail-drawer__top"><div><span className="eyebrow"><span className="eyebrow__line" />Incident intelligence</span><strong>{target.incident_id || target.id || 'Incident'}</strong></div><IconButton label="Close incident detail" onClick={onClose}><X size={17} /></IconButton></div>
      <div className="detail-drawer__hero"><span className={`detail-drawer__risk detail-drawer__risk--${riskClass(level)}`}>{target.risk_score ?? '—'}</span><div><span>risk score</span><strong>{attackLabel(target.risk_level || target.severity || 'unavailable')}</strong></div></div>
      <div className="detail-drawer__facts"><div><span>Entity</span><strong>{target.entity_id || '—'}</strong></div><div><span>Detection</span><strong>{attackLabel(target.attack_type || target.classification)}</strong></div><div><span>State</span><strong>{target.state || target.status || '—'}</strong></div><div><span>Created</span><strong>{formatDate(target.created_at || target.timestamp)}</strong></div></div>
      <Explainer detail={target} />
      <div className="recommendation"><span className="recommendation__label"><ShieldCheck size={15} /> Recommended defensive action</span><strong>{target.recommended_action || target.action || '—'}</strong><span className="recommendation__note">Loaded from the incident and policy response.</span></div>
    </aside>
  );
}

function PolicyPanel({ policy }) {
  const entries = policy && typeof policy === 'object' ? Object.entries(policy).slice(0, 7) : [];
  return <section className="policy-panel"><div className="panel__head"><div><div className="eyebrow"><span className="eyebrow__line" />Policy / control</div><h3>Human authority, <em>bounded.</em></h3></div><LockKeyhole size={21} /></div><p>Response actions remain accountable to the policy returned by the defense plane.</p>{entries.length ? <div className="policy-list">{entries.map(([key, value]) => <div key={key}><span>{key.replace(/_/g, ' ')}</span><strong>{typeof value === 'object' ? JSON.stringify(value) : String(value)}</strong></div>)}</div> : <DataStatus />}</section>;
}

function SystemStatus({ connection }) {
  const statuses = [{ label: 'Backend API', tone: connection.api ? 'green' : 'orange', value: connection.api ? 'reachable' : 'unavailable' }, { label: 'Live updates', tone: connection.ws ? 'green' : 'orange', value: connection.ws ? 'polling' : 'paused' }, { label: 'Data processing', tone: connection.api ? 'neutral' : 'orange', value: connection.api ? 'backend' : 'unavailable' }, { label: 'Threat intelligence', tone: connection.api ? 'neutral' : 'orange', value: connection.api ? 'backend' : 'unavailable' }, { label: 'Policy', tone: connection.api ? 'neutral' : 'orange', value: connection.api ? 'backend' : 'unavailable' }];
  return <section className="system-status"><div className="eyebrow"><span className="eyebrow__line" />Operational status</div><div className="system-status__list">{statuses.map((status) => <div key={status.label}><span className={`system-status__dot system-status__dot--${status.tone}`} /><span>{status.label}</span><strong>{status.value}</strong></div>)}</div></section>;
}

function AuditPanel({ audit }) {
  const chainVerified = canVerifyAuditChain(audit);
  return <section className="audit-section section" id="audit"><SectionKicker eyebrow="Audit & transparency / prove" title={<>Trust the <em>trail.</em></>} description="A clear record of what the system observed, what a human decided, and what was verified." action={<span className={`chain-status ${chainVerified ? 'chain-status--active' : ''}`}><Fingerprint size={15} />{chainVerified ? 'CHAIN INTACT' : 'VERIFICATION UNAVAILABLE'}</span>} /><div className="audit-table">{audit.length ? audit.map((entry, index) => <div className="audit-row" key={entry.id || entry.event_id || index}><span className="audit-row__type"><span className="audit-row__icon"><FileCheck2 size={15} /></span>{entry.event_type || entry.type || 'event'}</span><span>{formatDate(entry.timestamp || entry.created_at)}</span><span>{entry.incident_id || entry.incident || '—'}</span><span>{entry.details || entry.message || '—'}</span><span className="audit-row__hash">{entry.hash || entry.hash_value || '—'} <Copy size={13} /></span></div>) : <div className="audit-empty"><Fingerprint size={22} /><strong>{emptyMessage}</strong><span>Audit events will appear here when the backend records them.</span></div>}</div></section>;
}

function CapabilityStrip() {
  const capabilities = [{ number: '01', title: 'See', copy: 'Detect normal vs malicious activity before it becomes an incident.', image: images.network, icon: Eye, target: '#traffic' }, { number: '02', title: 'Understand', copy: 'Classify the signal and show the evidence behind the risk.', image: images.operations, icon: Gauge, target: '#incidents' }, { number: '03', title: 'Control', copy: 'Recommend a bounded response with human authorization.', image: images.infrastructure, icon: Target, target: '#policy' }, { number: '04', title: 'Verify', copy: 'Prove whether the threat actually decreased after response.', image: images.hero, icon: CheckCircle2, target: '#audit' }];
  return <section className="capability-section section"><SectionKicker eyebrow="The defense loop" title={<>From signal to<br /><em>certainty.</em></>} description="The product story is built around the questions a security team actually asks." /><div className="capability-grid">{capabilities.map(({ number, title, copy, image, icon: Icon, target }) => <article className="capability-card" key={number}><img src={image} alt="" /><div className="capability-card__wash" /><span className="capability-card__number">{number}</span><Icon className="capability-card__icon" size={19} /><div className="capability-card__copy"><span className="eyebrow">{title}</span><h3>{copy}</h3><a className="capability-card__link" href={target}>Explore <ArrowUpRight size={14} /></a></div></article>)}</div></section>;
}

function IncidentAlert({ incident, countdown, actionBusy, onDecision, onOverride, onClose }) {
  if (!incident) return null;
  const level = getRiskLevel(incident);
  const state = String(incident.state || '').toLowerCase();
  const decisionRequired = state === 'pending' || state === 'queued' || !state;
  const inExecution = state === 'executing' || state === 'timed_out' || state === 'verification';
  const isResolved = state === 'resolved';
  const isCancelled = state === 'cancelled';
  const factors = incident.fusion?.top_factors || incident.top_factors || [];
  const title = isResolved ? 'INCIDENT RESOLVED' : isCancelled ? 'DEFENSE CANCELLED' : inExecution ? (state === 'verification' ? 'THREAT REDUCED' : 'DEFENSE EXECUTING') : 'HIGH RISK ACTIVITY';
  const statusIcon = isResolved ? <CheckCircle2 size={16} /> : isCancelled ? <X size={16} /> : inExecution ? <ShieldCheck size={16} /> : <CircleAlert size={16} />;
  const modelOne = incident.model_1 || {};
  const modelTwo = incident.model_2 || {};
  const why = incident.assessment || incident.fusion?.assessment || (factors.length ? factors.join(' · ') : 'Low known-pattern resemblance combined with high behavioral deviation.');
  const defense = incident.recommended_action || 'PAUSE SUSPICIOUS PROCESS';
  return <div className="alert-backdrop"><section className={`incident-alert incident-alert--${riskClass(level)}`} role="dialog" aria-modal="true" aria-label="Threat detected"><div className="incident-alert__stripe" /><div className="incident-alert__head"><span className="eyebrow"><span className="eyebrow__line" />Live incident / decision required</span><IconButton label="Close alert" onClick={onClose}><X size={18} /></IconButton></div><div className="incident-alert__title"><div><span className="incident-alert__status">{statusIcon} {title}</span><h2>{attackLabel(incident.attack_type || incident.classification || 'Suspicious activity')}</h2><p>{incident.entity_id || 'Server-07'} · {incident.incident_id || incident.id || 'INC-007'}</p></div><div className="incident-alert__count"><span>{decisionRequired ? 'countdown' : 'stage'}</span><strong>{decisionRequired ? countdown ?? '—' : isResolved ? 'OK' : state === 'verification' ? 'VERIFY' : state === 'cancelled' ? 'MONITOR' : 'RUN'}</strong><small>{decisionRequired ? '30 second policy window' : 'backend simulation state'}</small></div></div><div className="incident-alert__grid"><div><span>What was detected</span><strong>{attackLabel(incident.attack_type || 'Previously unseen behavioral activity')}</strong></div><div><span>Model 1 result</span><strong>{modelOne.similarity ?? 12}% <em>{modelOne.attack_type || 'LOW known-pattern resemblance'}</em></strong></div><div><span>Model 2 result</span><strong>{modelTwo.anomaly_score ?? 94}/100 <em>{modelTwo.status || 'HIGH behavioral deviation'}</em></strong></div><div><span>Overall risk</span><strong>{incident.risk_score ?? 88} <em>{level || 'high'}</em></strong></div><div><span>Why suspicious</span><strong>{why}</strong></div><div><span>Recommended defense</span><strong>{defense}</strong></div></div><div className="incident-alert__actions">{decisionRequired ? <><button className="button button--critical" type="button" disabled={actionBusy} onClick={() => onDecision('stop')}>Stop <X size={16} /></button><button className="button button--light" type="button" disabled={actionBusy} onClick={() => onDecision('continue')}>Continue <ChevronRight size={16} /></button></> : <span className="incident-alert__hint">{isCancelled ? 'Defense cancelled. Continue monitoring Server-07.' : isResolved ? 'Defense verified. Monitoring continues.' : inExecution ? 'Authorization granted. Response is bounded by policy.' : 'The response remains bounded by policy.'}</span>}<span className="incident-alert__hint">{state === 'verification' ? 'Suspicious activity reduced · behavioral deviation returning toward baseline.' : isResolved ? 'Defense verified · incident resolved.' : ''}</span></div></section></div>;
}

function LoginScreen({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const submit = (event) => {
    event.preventDefault();
    if (username.trim().toLowerCase() === 'admin@aegisflow.demo' && password === 'demo123') {
      localStorage.setItem(DEMO_SESSION_KEY, '1');
      onLogin();
      return;
    }
    setError('Use the demo credentials shown below.');
  };

  return <div className="login-shell"><div className="login-card"><div className="login-card__brand"><span className="brand__mark"><span /><span /><span /></span><span><strong>AEGISFLOW</strong><small>Cyber Defense Platform</small></span></div><div className="eyebrow"><span className="eyebrow__line" />AI-powered cyber defense</div><h1>See the threat.<br /><em>Control</em> the response.</h1><p>Review threats, understand the evidence, and control authorized response from one defense plane.</p><form onSubmit={submit} className="login-form"><label htmlFor="demo-username">Email</label><input id="demo-username" autoComplete="username" type="email" value={username} onChange={(event) => setUsername(event.target.value)} placeholder="admin@aegisflow.demo" required /><label htmlFor="demo-password">Password</label><input id="demo-password" type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="demo123" required />{error && <div className="login-error" role="alert">{error}</div>}<button className="button button--primary login-form__submit" type="submit">Sign in <ChevronRight size={16} /></button></form><div className="login-demo"><span>Demo credentials</span><strong>admin@aegisflow.demo / demo123</strong></div></div><div className="login-visual"><img src={images.hero} alt="Abstract security operations visual" /><div className="login-visual__wash" /><div className="login-visual__copy"><span className="eyebrow"><span className="eyebrow__line" />Human-authorized defense</span><strong>See the threat.<br /><em>Control</em> the response.</strong></div></div></div>;
}

function DemoControls({ state, busy, onStart, onReset }) {
  const running = state?.mode === 'running';
  const completed = state?.mode === 'resolved';
  const stage = state?.stage || (completed ? 'RESOLVED' : 'READY');
  return <section className="demo-console" aria-label="Demonstration controls"><div><div className="eyebrow"><span className="eyebrow__line" />Hackathon demo / simulated</div><strong>{running ? `Scenario running · ${stage} · step ${state.stage_index ?? state.step ?? 0} of ${state.stage_count ?? 10}` : completed ? 'Incident resolved · verification complete' : 'Ready for the Server-07 scenario'}</strong><span>Illustrative values only — not production accuracy or a confirmed zero-day.</span></div><div className="demo-console__actions"><button className="button button--primary" type="button" disabled={busy || running} onClick={onStart}>{busy ? 'Starting…' : running ? 'Demo running' : 'Start Demo'} <Zap size={15} /></button><button className="button button--outline" type="button" disabled={busy} onClick={onReset}>Reset scenario <RefreshCw size={14} /></button></div></section>;
}

function TimelineView({ timeline, incidents }) {
  if (!timeline.length) return <Timeline incidents={incidents} />;
  const groups = timeline.reduce((result, item) => { const key = item.entity_id || 'Unknown entity'; result[key] = result[key] || []; result[key].push(item); return result; }, {});
  return <section className="section timeline-section" id="timeline"><SectionKicker eyebrow="Attack timeline / understand" title={<>Follow the <em>story.</em></>} description="A seeded demonstration chain shows how signals progress from reconnaissance to verification." /><div className="timeline-layout"><div className="timeline-intro"><span className="timeline-intro__number">03</span><h3>From signal<br />to <em>proof.</em></h3><p>Every stage below is simulated locally so the complete defense loop can be demonstrated without customer telemetry.</p><span className="timeline-intro__rule" /></div><div className="timeline-content">{Object.entries(groups).map(([entity, rows]) => <div className="timeline-group" key={entity}><div className="timeline-group__head"><span className="timeline-group__entity">{entity}</span><span>{rows.length} connected stages</span></div><div className="timeline-steps">{rows.map((item, index) => <div className="timeline-step" key={`${item.timeline_id || item.timestamp}-${item.attack_stage}`}><span className="timeline-step__dot" /><span className="timeline-step__label">{item.attack_stage}</span><span className="timeline-step__date">{formatDate(item.timestamp)} · {item.status}</span>{index < rows.length - 1 && <span className="timeline-step__connector" />}<small className="timeline-step__event">{item.event}</small></div>)}</div></div>)}</div></div></section>;
}

const routeItems = [
  { path: '/dashboard', label: 'Dashboard', icon: Gauge },
  { path: '/live-traffic', label: 'Live Traffic', icon: Activity },
  { path: '/incidents', label: 'Incidents', icon: CircleAlert },
  { path: '/attack-timeline', label: 'Attack Timeline', icon: Layers3 },
  { path: '/audit', label: 'Audit & Transparency', icon: Fingerprint },
  { path: '/policy', label: 'Policy', icon: LockKeyhole },
  { path: '/simulation', label: 'Simulation', icon: Radio },
];

function PageHeader({ eyebrow, title, description, action }) {
  return <div className="page-header"><div><div className="eyebrow"><span className="eyebrow__line" />{eyebrow}</div><h1>{title}</h1>{description && <p>{description}</p>}</div>{action}</div>;
}

function AppSidebar({ path, onNavigate, onLogout, connection }) {
  return <aside className="sidebar"><button className="sidebar__brand" type="button" onClick={() => onNavigate('/dashboard')}><span className="brand__mark"><span /><span /><span /></span><span><strong>AEGISFLOW</strong><small>Cyber Defense Platform</small></span></button><div className="sidebar__label">Command center</div><nav className="sidebar__nav">{routeItems.map(({ path: target, label, icon: Icon }) => <button className={path === target || (target === '/incidents' && path.startsWith('/incidents/')) ? 'sidebar-link sidebar-link--active' : 'sidebar-link'} type="button" key={target} onClick={() => onNavigate(target)}><Icon size={16} /><span>{label}</span></button>)}</nav><div className="sidebar__bottom"><div className="sidebar-status"><span className={`system-status__dot system-status__dot--${connection.api ? 'green' : 'orange'}`} /><span>Backend</span><strong>{connection.api ? 'Connected' : 'Offline'}</strong></div><div className="sidebar-user"><span className="avatar">AF</span><div><strong>Admin</strong><small>Demo operator</small></div><button type="button" onClick={onLogout} aria-label="Log out" title="Log out"><ExternalLink size={14} /></button></div></div></aside>;
}

function AppHeader({ path, onLogout, onNavigate, pendingApprovals, connection }) {
  const current = routeItems.find((item) => item.path === path) || routeItems.find((item) => item.path === '/incidents' && path.startsWith('/incidents/'));
  return <header className="app-header"><button className="header-back" type="button" onClick={() => onNavigate('/dashboard')}><span className="brand__mark"><span /><span /><span /></span><strong>AEGISFLOW</strong></button><div className="header-title"><span>{current?.label || 'Incident detail'}</span><small>{connection.api ? 'Backend connected · simulated state available' : 'Backend unavailable · retrying'}</small></div><div className="header-tools"><StatusMarker label={connection.api ? 'Connected' : 'Offline'} tone={connection.api ? 'green' : 'orange'} /><span className="notification-count">{pendingApprovals.length}</span><button className="avatar avatar-button" type="button" title="Log out" onClick={onLogout}>AF</button></div></header>;
}

function ModelStatusPanel({ connection, demoState }) {
  const active = connection.api;
  const rows = [{ label: 'Model 1', name: 'Known-pattern recognition', value: active ? 'ACTIVE' : 'OFFLINE' }, { label: 'Model 2', name: 'Behavioral anomaly detection', value: active ? 'ACTIVE' : 'OFFLINE' }, { label: 'Threat fusion', name: demoState.step >= 2 ? 'Signal fusion running' : 'Ready for live traffic', value: active ? 'ACTIVE' : 'OFFLINE' }, { label: 'Defense', name: 'Human-authorized response', value: active ? 'READY' : 'OFFLINE' }, { label: 'Verification', name: 'Closed-loop effectiveness', value: active ? 'READY' : 'OFFLINE' }];
  return <section className="model-status-panel"><div className="panel__head"><div><div className="eyebrow"><span className="eyebrow__line" />Platform readiness</div><h3>Signal to <em>response.</em></h3></div><ShieldCheck size={22} /></div><div className="model-status-list">{rows.map((row) => <div key={row.label}><span className={`system-status__dot system-status__dot--${active ? 'green' : 'orange'}`} /><div><strong>{row.label}</strong><small>{row.name}</small></div><b>{row.value}</b></div>)}</div></section>;
}

function IncidentHistoryTable({ incidents, onOpen }) {
  return <section className="history-panel"><div className="history-panel__head"><div><div className="eyebrow"><span className="eyebrow__line" />Persistent history</div><h3>Incident <em>ledger.</em></h3></div><span className="history-count">{incidents.length} records · demo state</span></div><div className="history-table"><div className="history-table__header"><span>Incident</span><span>Timestamp</span><span>Entity</span><span>Attack type</span><span>Risk</span><span>Confidence</span><span>Behavior</span><span>Status</span></div>{incidents.map((incident) => <button className="history-row" type="button" key={incident.incident_id} onClick={() => onOpen(incident)}><strong>{incident.incident_id}</strong><span>{formatDate(incident.created_at)}</span><span>{incident.entity_id}</span><span>{incident.attack_type}</span><b className={`risk-text risk-text--${riskClass(getRiskLevel(incident))}`}>{incident.risk_level}</b><span>{incident.confidence_percent ?? `${Math.round((incident.confidence || 0) * 100)}%`}</span><span>{incident.behavioral_deviation ?? '—'}/100</span><span className="history-status">{incident.status}</span><ChevronRight size={15} /></button>)}</div></section>;
}

function DashboardPage({ metrics, policy, incidents, traffic, connection, demoState, onOpen, onStart, onReset, demoBusy }) {
  const active = incidents.filter((item) => !['RESOLVED', 'CLOSED'].includes(item.status)).slice(0, 5);
  return <main className="page-main"><PageHeader eyebrow="Security command center / dashboard" title={<>See the threat.<br /><em>Control</em> the response.</>} description="A live view of local telemetry, explainable risk, and human-authorized defense." action={<button className="button button--primary" type="button" disabled={demoBusy || demoState.mode === 'running'} onClick={onStart}>{demoState.mode === 'running' ? 'Simulation running' : 'Start live simulation'} <Zap size={15} /></button>} /><DemoControls state={demoState} busy={demoBusy} onStart={onStart} onReset={onReset} /><MetricBand metrics={metrics} /><div className="dashboard-grid"><TrafficPanel traffic={traffic} /><ModelStatusPanel connection={connection} demoState={demoState} /></div><div className="dashboard-grid dashboard-grid--lower"><section className="active-panel"><div className="panel__head"><div><div className="eyebrow"><span className="eyebrow__line" />Active incidents</div><h3>Attention, <em>with context.</em></h3></div><button className="button button--outline" type="button" onClick={() => onOpen({ route: '/incidents' })}>View history <ArrowUpRight size={14} /></button></div>{active.map((incident) => <button className="active-incident" type="button" key={incident.incident_id} onClick={() => onOpen(incident)}><span className={`active-incident__rail active-incident__rail--${riskClass(getRiskLevel(incident))}`} /><span><strong>{incident.incident_id}</strong><small>{incident.entity_id} · {incident.attack_type}</small></span><b>{incident.risk_level}</b><span>{incident.status}</span><ChevronRight size={15} /></button>)}</section><PolicyPanel policy={policy} /></div><SystemStatus connection={{ api: connection.api, ws: connection.api }} /></main>;
}

function LiveTrafficPage({ traffic, behavior, knownPattern, demoState, demoBusy, onStart, onReset }) {
  const current = traffic[traffic.length - 1] || {};
  return <main className="page-main"><PageHeader eyebrow="Live signal / observe" title={<>The system is always<br /><em>listening.</em></>} description="Watch trusted baseline activity develop into a suspicious behavioral signal through backend-driven simulation." action={<button className="button button--primary" type="button" disabled={demoBusy || demoState.mode === 'running'} onClick={onStart}>Start live simulation <Radio size={15} /></button>} /><DemoControls state={demoState} busy={demoBusy} onStart={onStart} onReset={onReset} /><div className="live-traffic-grid"><TrafficPanel traffic={traffic} /><section className="baseline-panel"><div className="panel__head"><div><div className="eyebrow"><span className="eyebrow__line" />Model 2 / compare</div><h3>Baseline versus <em>now.</em></h3></div><StatusMarker label={current.status || 'NORMAL'} tone={current.status === 'SUSPICIOUS' ? 'orange' : 'green'} /></div><div className="baseline-values"><div><span>Trusted requests / min</span><strong>800–1,200</strong><small>Server-07 baseline</small></div><div><span>Current requests / min</span><strong>{current.requests_per_min ?? '—'}</strong><small>{current.status || 'waiting'}</small></div><div><span>Trusted destinations</span><strong>10–25</strong><small>normal diversity</small></div><div><span>Current destinations</span><strong>{current.unique_destinations ?? '—'}</strong><small>live observation</small></div><div><span>Behavioral deviation</span><strong>{behavior?.behavioral_deviation ?? '—'}/100</strong><small>{behavior?.severity || 'awaiting signal'}</small></div><div><span>Known-pattern similarity</span><strong>{knownPattern?.current?.similarity ?? '—'}%</strong><small>low resemblance is not zero-day confirmation</small></div></div><div className="illustrative-note">Illustrative demonstration values · raw telemetry remains local to the demo backend.</div></section></div></main>;
}

function IncidentDetailPage({ incident, onBack, onDecision }) {
  if (!incident) return <main className="page-main"><DataStatus>Loading incident detail</DataStatus></main>;
  const auth = incident.authorization || {};
  const defense = incident.defense || {};
  const verification = incident.verification || {};
  const pending = auth.status === 'PENDING' || defense.status === 'PENDING';
  return <main className="page-main"><button className="back-link" type="button" onClick={onBack}>← Back to incidents</button><PageHeader eyebrow="Incident intelligence / detail" title={<>{incident.incident_id}<br /><em>{incident.attack_type}</em></>} description={`${incident.entity_id} · ${incident.demo_label || 'backend record'}`} /><div className="incident-detail-grid"><section className="incident-overview-card"><div className="incident-score"><span>Risk score</span><strong>{incident.risk_score}</strong><b className={`risk-text risk-text--${riskClass(getRiskLevel(incident))}`}>{incident.risk_level}</b></div><div className="detail-facts"><div><span>Entity</span><strong>{incident.entity_id}</strong></div><div><span>Confidence</span><strong>{incident.confidence_percent}%</strong></div><div><span>Known-pattern similarity</span><strong>{incident.known_pattern_similarity}% · {incident.model_1?.attack_type}</strong></div><div><span>Behavioral deviation</span><strong>{incident.behavioral_deviation}/100 · {incident.model_2?.anomaly_score}</strong></div><div><span>Authorization</span><strong>{auth.status || 'PENDING'}</strong></div><div><span>Defense</span><strong>{defense.status || 'PENDING'}</strong></div><div><span>Verification</span><strong>{verification.status || 'PENDING'}</strong></div><div><span>Assessment</span><strong>{incident.assessment}</strong></div></div>{pending && <div className="decision-bar"><span>Human decision required · 30 second policy window</span><div><button className="button button--critical" type="button" onClick={() => onDecision('stop', incident)}>Stop</button><button className="button button--light" type="button" onClick={() => onDecision('continue', incident)}>Continue</button></div></div>}</section><section className="detail-side-card"><Explainer detail={incident} /><div className="recommendation"><span className="recommendation__label"><ShieldCheck size={15} /> Recommended response</span><strong>{incident.recommended_action}</strong><span className="recommendation__note">{incident.recommendation?.rationale || 'Loaded from backend policy.'}</span></div></section></div><section className="detail-timeline"><SectionKicker eyebrow="Incident chain / evidence" title={<>Every signal leaves a <em>trace.</em></>} description="The linked event sequence is retained in the local demo audit model." /><div className="detail-event-grid">{(incident.explanation || []).map((factor) => <div key={factor.factor}><span>{factor.factor}</span><strong>+{factor.contribution}</strong><small>{factor.explanation}</small></div>)}</div>{verification.status && <div className="verification-callout"><CheckCircle2 size={20} /><div><strong>{verification.label}</strong><span>Before {verification.before_value}/min → After {verification.after_value}/min · Reduction {verification.reduction_percent}%</span></div></div>}</section></main>;
}

function AuditPage({ audit }) {
  return <main className="page-main"><PageHeader eyebrow="Audit & transparency / prove" title={<>Trust the <em>trail.</em></>} description="Every simulated processing step is recorded with timestamp, action, actor, entity and result." /><AuditPanel audit={audit} /></main>;
}

function PolicyPage({ policy, connection }) {
  return <main className="page-main"><PageHeader eyebrow="Policy / authority" title={<>Human authority, <em>bounded.</em></>} description="Policy sits between model output and response execution. The demo never gives an AI unrestricted authority." /><div className="policy-page-grid"><PolicyPanel policy={policy} /><section className="policy-matrix"><div className="eyebrow"><span className="eyebrow__line" />Risk policy</div>{[['LOW', 'Monitor'], ['MEDIUM', 'Restrict / Pause'], ['HIGH', 'Isolate / Restrict'], ['CRITICAL', 'Immediate containment if pre-authorized']].map(([risk, action]) => <div key={risk}><strong>{risk}</strong><span>{action}</span></div>)}<div className="policy-page-note"><ShieldCheck size={17} /> Human authorization required · fail-safe timeout 30 seconds</div></section></div><SystemStatus connection={{ api: connection.api, ws: connection.api }} /></main>;
}

function SimulationPage({ demoState, demoBusy, traffic, behavior, knownPattern, incidents, audit, onStart, onReset, onOpen }) {
  const phases = ['Normal', 'Traffic anomaly', 'Model 1 analysis', 'Model 2 behavior analysis', 'Threat fusion', 'High risk alert', 'User authorization', 'Defense', 'Verification', 'Resolved'];
  const activePhase = Number.isFinite(demoState.stage_index) ? demoState.stage_index : Math.min(demoState.step || 0, phases.length - 1);
  return <main className="page-main"><PageHeader eyebrow="Simulation / demonstrate" title={<>Make the defense loop <em>visible.</em></>} description="Run the complete Server-07 scenario from normal behavior to explainable risk, human control and verification." action={<button className="button button--primary" type="button" disabled={demoBusy || demoState.mode === 'running'} onClick={onStart}>Start attack simulation <Zap size={15} /></button>} /><DemoControls state={demoState} busy={demoBusy} onStart={onStart} onReset={onReset} /><section className="simulation-stage"><div className="simulation-stage__head"><div><div className="eyebrow"><span className="eyebrow__line" />Live scenario / Server-07</div><h3>Normal <em>→</em> suspicious <em>→</em> verified</h3></div><StatusMarker label={demoState.stage || (demoState.mode === 'idle' ? 'READY' : 'RUNNING')} tone={demoState.mode === 'running' ? 'orange' : demoState.mode === 'resolved' ? 'green' : 'neutral'} /></div><div className="phase-track">{phases.map((phase, index) => <div className={index <= activePhase ? 'phase phase--active' : 'phase'} key={phase}><span>{String(index + 1).padStart(2, '0')}</span><strong>{phase}</strong>{index < phases.length - 1 && <i />}</div>)}</div><div className="simulation-evidence"><div><span>Requests / min</span><strong>{traffic[traffic.length - 1]?.requests_per_min ?? '—'}</strong><small>{traffic[traffic.length - 1]?.status || 'NORMAL'}</small></div><div><span>Model 1 resemblance</span><strong>{knownPattern?.current?.similarity ?? '—'}%</strong><small>{knownPattern?.current?.status || 'awaiting analysis'}</small></div><div><span>Model 2 deviation</span><strong>{behavior?.behavioral_deviation ?? '—'}/100</strong><small>{behavior?.status || behavior?.severity || 'baseline'}</small></div><div><span>Audit events</span><strong>{audit.length}</strong><small>backend records</small></div></div></section><IncidentHistoryTable incidents={incidents.slice(0, 10)} onOpen={onOpen} /></main>;
}

function AuthenticatedRouter({ incidents, traffic, timeline, audit, metrics, policy, behavior, knownPattern, demoState, demoBusy, connection, pendingApprovals, loadError, detail, liveIncident, countdown, actionBusy, actionError, onOpenDetail, onDecision, onStart, onReset, onLogout, onCloseIncident }) {
  const [path, setPath] = useState(() => window.location.pathname || '/dashboard');
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const navigate = useCallback((target) => { window.history.pushState({}, '', target); setPath(target); setSidebarOpen(false); window.scrollTo(0, 0); }, []);
  useEffect(() => {
    const onPopState = () => setPath(window.location.pathname || '/dashboard');
    window.addEventListener('popstate', onPopState);
    if (path === '/' || path === '/login') { window.history.replaceState({}, '', '/dashboard'); setPath('/dashboard'); }
    return () => window.removeEventListener('popstate', onPopState);
  }, [path]);
  const openIncident = useCallback((incident) => { if (incident?.route) { navigate(incident.route); return; } const id = incident?.incident_id || incident?.id; if (id) { navigate(`/incidents/${id}`); onOpenDetail(incident); } }, [navigate, onOpenDetail]);
  const detailId = path.startsWith('/incidents/') ? path.split('/')[2] : null;
  const selectedIncident = detailId ? (detail?.incident_id === detailId ? detail : incidents.find((item) => item.incident_id === detailId)) : null;
  useEffect(() => {
    if (detailId && !selectedIncident) onOpenDetail({ incident_id: detailId, source_type: 'incident' });
  }, [detailId, selectedIncident, onOpenDetail]);
  const page = path === '/dashboard' ? <DashboardPage metrics={metrics} policy={policy} incidents={incidents} traffic={traffic} connection={connection} demoState={demoState} onOpen={openIncident} onStart={onStart} onReset={onReset} demoBusy={demoBusy} /> : path === '/live-traffic' ? <LiveTrafficPage traffic={traffic} behavior={behavior} knownPattern={knownPattern} demoState={demoState} demoBusy={demoBusy} onStart={onStart} onReset={onReset} /> : path === '/incidents' ? <main className="page-main"><PageHeader eyebrow="Incident history / decide" title={<>Attention, <em>with context.</em></>} description="Persistent backend records with evidence, confidence, risk and response state." /><IncidentHistoryTable incidents={incidents} onOpen={openIncident} /></main> : detailId ? <IncidentDetailPage incident={selectedIncident} onBack={() => navigate('/incidents')} onDecision={onDecision} /> : path === '/attack-timeline' ? <main className="page-main"><TimelineView timeline={timeline} incidents={incidents} /></main> : path === '/audit' ? <AuditPage audit={audit} /> : path === '/policy' ? <PolicyPage policy={policy} connection={connection} /> : path === '/simulation' ? <SimulationPage demoState={demoState} demoBusy={demoBusy} traffic={traffic} behavior={behavior} knownPattern={knownPattern} incidents={incidents} audit={audit} onStart={onStart} onReset={onReset} onOpen={openIncident} /> : <DashboardPage metrics={metrics} policy={policy} incidents={incidents} traffic={traffic} connection={connection} demoState={demoState} onOpen={openIncident} onStart={onStart} onReset={onReset} demoBusy={demoBusy} />;
  return <div className="route-shell"><div className={sidebarOpen ? 'sidebar-wrap sidebar-wrap--open' : 'sidebar-wrap'}><AppSidebar path={path} onNavigate={navigate} onLogout={onLogout} connection={connection} /></div><div className="route-content"><AppHeader path={path} onLogout={onLogout} onNavigate={navigate} pendingApprovals={pendingApprovals} connection={connection} /><button className="mobile-sidebar-toggle" type="button" onClick={() => setSidebarOpen((value) => !value)} aria-label="Open navigation"><Menu size={19} /></button>{loadError && <div className="integration-banner" role="status"><CircleAlert size={15} />{loadError}</div>}{page}<footer className="route-footer"><span>AEGISFLOW / {DEMO_LABEL}</span><span>Raw telemetry remains in the local demo boundary.</span></footer>{actionError && <div className="action-toast" role="alert"><CircleAlert size={16} /><span>{actionError}</span><button type="button" onClick={() => onCloseIncident('error')} aria-label="Dismiss message"><X size={15} /></button></div>}<IncidentAlert incident={liveIncident} countdown={countdown} actionBusy={actionBusy} onDecision={onDecision} onOverride={() => onDecision('stop')} onClose={() => onCloseIncident()} /></div></div>;
}

function IntegratedApp() {
  const [authenticated, setAuthenticated] = useState(() => localStorage.getItem(DEMO_SESSION_KEY) === '1');
  const [incidents, setIncidents] = useState([]);
  const [traffic, setTraffic] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [audit, setAudit] = useState([]);
  const [metrics, setMetrics] = useState(null);
  const [policy, setPolicy] = useState(null);
  const [behavior, setBehavior] = useState(null);
  const [knownPattern, setKnownPattern] = useState(null);
  const [pendingApprovals, setPendingApprovals] = useState([]);
  const [demoState, setDemoState] = useState({ mode: 'idle', step: 0 });
  const [demoBusy, setDemoBusy] = useState(false);
  const [selected, setSelected] = useState(null);
  const [detail, setDetail] = useState(null);
  const [liveIncident, setLiveIncident] = useState(null);
  const [countdown, setCountdown] = useState(null);
  const [actionBusy, setActionBusy] = useState(false);
  const [actionError, setActionError] = useState('');
  const [loadError, setLoadError] = useState('');
  const [lastUpdated, setLastUpdated] = useState(null);
  const [connection, setConnection] = useState({ api: false, polling: false });
  const [mobileMenu, setMobileMenu] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [notificationsOpen, setNotificationsOpen] = useState(false);

  const fetchJson = useCallback(async (path, options = {}) => {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 10000);
    try {
      const response = await fetch(`${API_BASE}${path}`, { ...options, signal: controller.signal });
      const text = await response.text();
      let payload = {};
      try { payload = text ? JSON.parse(text) : {}; } catch { payload = { message: text }; }
      if (!response.ok) throw new Error(payload.message || `${path} returned ${response.status}`);
      return payload;
    } finally {
      window.clearTimeout(timeout);
    }
  }, []);

  const loadData = useCallback(async () => {
    const requests = [
      ['health', '/health'],
      ['dashboard', '/api/dashboard'],
      ['incidents', '/api/incidents'],
      ['alerts', '/api/alerts?hours=24'],
      ['defenses', '/api/defense'],
      ['traffic', '/api/traffic/live'],
      ['timeline', '/api/timeline'],
      ['audit', '/api/audit'],
      ['demoState', '/api/demo/state'],
      ['behavior', '/api/models/behavior'],
      ['knownPattern', '/api/models/known-pattern'],
    ];
    const results = await Promise.allSettled(requests.map(([, path]) => fetchJson(path)));
    const byName = Object.fromEntries(results.map((result, index) => [requests[index][0], result]));
    const dashboard = byName.dashboard.status === 'fulfilled' ? byName.dashboard.value : null;
    const incidentPayload = byName.incidents.status === 'fulfilled' ? byName.incidents.value : null;
    const alertPayload = byName.alerts.status === 'fulfilled' ? byName.alerts.value : null;
    const trafficPayload = byName.traffic.status === 'fulfilled' ? byName.traffic.value : null;
    const timelinePayload = byName.timeline.status === 'fulfilled' ? byName.timeline.value : null;
    const auditPayload = byName.audit.status === 'fulfilled' ? byName.audit.value : null;
    const demoPayload = byName.demoState.status === 'fulfilled' ? byName.demoState.value : null;
    const behaviorPayload = byName.behavior.status === 'fulfilled' ? byName.behavior.value : null;
    const knownPatternPayload = byName.knownPattern.status === 'fulfilled' ? byName.knownPattern.value : null;
    const incidentRecords = getArray(incidentPayload, ['incidents', 'data']).map((item) => normalizeIncident({ ...item, source_type: 'incident' }));
    const alertRecords = getArray(alertPayload || dashboard, ['alerts', 'recent_alerts', 'data']).map(normalizeAlert);
    const nextIncidents = incidentRecords.length ? incidentRecords : alertRecords;
    const apiWorked = byName.health.status === 'fulfilled' || byName.dashboard.status === 'fulfilled';
    setConnection({ api: apiWorked, polling: true });
    if (!apiWorked) setLoadError('The backend is unavailable. Retrying automatically.');
    else setLoadError('');
    setIncidents(nextIncidents);
    const latestSimulationIncident = nextIncidents.find((item) => item.incident_id === 'INC-007');
    setDetail((current) => current && latestSimulationIncident && current.incident_id === latestSimulationIncident.incident_id ? { ...current, ...latestSimulationIncident } : current);
    setTraffic(getArray(trafficPayload, ['traffic', 'data']));
    setTimeline(getArray(timelinePayload, ['timeline', 'data']));
    setAudit(getArray(auditPayload, ['events', 'audit', 'data']));
    if (behaviorPayload) setBehavior(behaviorPayload);
    if (knownPatternPayload) setKnownPattern(knownPatternPayload);
    if (demoPayload) setDemoState(demoPayload);
    if (dashboard) {
      const threat = dashboard.threat_summary || {};
      const posture = dashboard.security_posture || {};
      setMetrics(dashboard.metrics || { ...threat, total_incidents: incidentRecords.length || alertRecords.length, risk_distribution: { critical: threat.critical_risks || 0, high: threat.high_risks || 0, medium: threat.medium_risks || 0, low: threat.low_risks || 0 } });
      setPolicy(dashboard.policy || { authorization: dashboard.authorization_summary, certification: dashboard.system_status?.certification_status, monitoring: posture });
      const pending = getArray(dashboard, ['pending_approvals']);
      setPendingApprovals(pending);
      const decisionWindowOpen = demoPayload?.mode === 'running' && demoPayload?.stage_index >= 6 && pending[0];
      const pendingIncident = latestSimulationIncident || {};
      const pendingRecord = pending[0] ? normalizePendingApproval({ ...pending[0], ...pendingIncident }) : null;
      setLiveIncident((current) => {
        if (decisionWindowOpen) return current || pendingRecord;
        const latest = latestSimulationIncident || current;
        const followup = current && (['executing', 'verification', 'resolved', 'cancelled', 'timed_out'].includes(String(current.state).toLowerCase()) || latest?.authorization?.status === 'TIMED_OUT');
        if (followup) return { ...current, ...(latest || {}), state: current.state === 'cancelled' ? 'cancelled' : simulationUiState(demoPayload?.mode, latest) };
        return null;
      });
      if (decisionWindowOpen) setCountdown((current) => current === null ? (pending[0].timeout_seconds || pending[0].controls?.countdown || 0) : Math.min(current, pending[0].timeout_seconds || pending[0].controls?.countdown || 0));
      else setCountdown(null);
    }
    setLastUpdated(new Date().toISOString());
  }, [fetchJson]);

  const openDetail = useCallback(async (incident) => {
    setSelected(incident);
    setDetail(null);
    const id = incident.incident_id || incident.id;
    if (!id || incident.source_type !== 'incident') return;
    try { const data = await fetchJson(`/api/incidents/${encodeURIComponent(id)}`); setDetail(normalizeIncident(data?.incident || data)); } catch { setDetail(incident); }
  }, [fetchJson]);

  useEffect(() => {
    if (!authenticated) return undefined;
    loadData();
    const timer = window.setInterval(loadData, 2500);
    return () => window.clearInterval(timer);
  }, [authenticated, loadData]);

  const startDemo = async () => {
    setDemoBusy(true);
    setActionError('');
    try { setDemoState(await fetchJson('/api/demo/start', { method: 'POST' })); await loadData(); }
    catch (error) { setActionError(error.message || 'The demonstration could not start.'); }
    finally { setDemoBusy(false); }
  };

  const resetDemo = async () => {
    setDemoBusy(true);
    setActionError('');
    try { setLiveIncident(null); setDemoState(await fetchJson('/api/demo/reset', { method: 'POST' })); await loadData(); }
    catch (error) { setActionError(error.message || 'The demonstration could not reset.'); }
    finally { setDemoBusy(false); }
  };

  const submitDecision = async (decision, target = liveIncident) => {
    const id = target?.defense_id || target?.action_id || target?.id || target?.defense?.defense_id;
    if (!id) { setActionError('This record has no backend defense action to authorize.'); return; }
    setActionBusy(true);
    setActionError('');
    try {
      const backendDecision = decision === 'continue' ? 'CONTINUE' : decision === 'timeout' ? 'TIMEOUT' : 'STOP';
      const result = await fetchJson(`/api/defense/${encodeURIComponent(id)}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ decision: backendDecision }) });
      if (result?.error) throw new Error(result.error);
      const resultIncident = normalizeIncident(result?.incident || result);
      setLiveIncident((current) => current ? { ...current, ...resultIncident, state: decision === 'continue' ? 'executing' : decision === 'timeout' ? 'timed_out' : 'cancelled' } : { ...resultIncident, state: decision === 'continue' ? 'executing' : decision === 'timeout' ? 'timed_out' : 'cancelled' });
      await loadData();
    } catch (error) { setActionError(error.name === 'AbortError' ? 'The backend request timed out.' : error.message || 'The backend could not process this decision.'); }
    finally { setActionBusy(false); }
  };

  useEffect(() => {
    if (!liveIncident) return undefined;
    const timer = window.setInterval(() => {
      setCountdown((value) => value === null || value <= 0 ? value : value - 1);
    }, 1000);
    return () => window.clearInterval(timer);
  }, [liveIncident]);

  const submitOverride = () => submitDecision('stop');
  const logout = () => { localStorage.removeItem(DEMO_SESSION_KEY); window.history.pushState({}, '', '/'); setAuthenticated(false); };
  const filteredIncidents = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    if (!query) return incidents;
    return incidents.filter((item) => JSON.stringify(item).toLowerCase().includes(query));
  }, [incidents, searchQuery]);
  const systemCopy = lastUpdated ? `Backend polling active · updated ${formatDate(lastUpdated)}` : 'Connecting to backend';

  if (!authenticated) {
    if (window.location.pathname !== '/' && window.location.pathname !== '/login') window.history.replaceState({}, '', '/login');
    return <LoginScreen onLogin={() => { localStorage.setItem(DEMO_SESSION_KEY, '1'); window.history.pushState({}, '', '/dashboard'); setAuthenticated(true); }} />;
  }

  return <AuthenticatedRouter incidents={filteredIncidents} traffic={traffic} timeline={timeline} audit={audit} metrics={metrics} policy={policy} behavior={behavior} knownPattern={knownPattern} demoState={demoState} demoBusy={demoBusy} connection={connection} pendingApprovals={pendingApprovals} loadError={loadError} detail={detail} liveIncident={liveIncident} countdown={countdown} actionBusy={actionBusy} actionError={actionError} onOpenDetail={openDetail} onDecision={submitDecision} onStart={startDemo} onReset={resetDemo} onLogout={logout} onCloseIncident={(reason) => reason === 'error' ? setActionError('') : setLiveIncident(null)} />;

  return <div className="app-shell">
    <header className="topbar"><a className="brand" href="#overview"><span className="brand__mark"><span /><span /><span /></span><span><strong>AEGISFLOW</strong><small>Cyber Defense Platform</small></span></a><nav className={mobileMenu ? 'nav nav--open' : 'nav'}>{['Overview', 'Incidents', 'Live Traffic', 'Attack Timeline', 'Audit & Transparency', 'Policy'].map((item) => <a href={`#${item === 'Overview' ? 'overview' : item === 'Incidents' ? 'incidents' : item === 'Live Traffic' ? 'traffic' : item === 'Attack Timeline' ? 'timeline' : item === 'Audit & Transparency' ? 'audit' : 'policy'}`} key={item} onClick={() => setMobileMenu(false)}>{item}</a>)}</nav><div className="topbar__tools"><IconButton label={searchOpen ? 'Close search' : 'Search'} onClick={() => setSearchOpen((value) => !value)}><Search size={17} /></IconButton><IconButton label="Notifications" onClick={() => setNotificationsOpen((value) => !value)}><Bell size={17} /></IconButton><StatusMarker label={connection.api ? 'Polling' : 'Offline'} tone={connection.api ? 'green' : 'orange'} /><button className="avatar avatar-button" type="button" title="Log out" aria-label="Log out" onClick={logout}>AF</button></div>{searchOpen && <div className="search-popover"><Search size={15} /><input autoFocus value={searchQuery} onChange={(event) => setSearchQuery(event.target.value)} placeholder="Search incidents and alerts" /></div>}{notificationsOpen && <div className="notification-popover"><strong>Pending authorization</strong>{pendingApprovals.length ? pendingApprovals.map((item) => <button type="button" key={item.auth_request_id || item.action_id} onClick={() => { setLiveIncident(normalizePendingApproval(item)); setNotificationsOpen(false); }}>{item.entity_id || item.alert?.entity || 'Security event'}<span>{item.status || 'pending'}</span></button>) : <span>No pending approvals from the backend.</span>}</div>}<button className="mobile-menu" type="button" aria-label="Toggle navigation" onClick={() => setMobileMenu((value) => !value)}><Menu size={20} /></button></header>
    {loadError && <div className="integration-banner" role="status"><CircleAlert size={15} />{loadError}</div>}
    <main><Hero /><DemoControls state={demoState} busy={demoBusy} onStart={startDemo} onReset={resetDemo} /><MetricBand metrics={metrics} /><SignalSection traffic={traffic} /><IncidentsSection incidents={filteredIncidents} onOpen={openDetail} /><TimelineView timeline={timeline} incidents={filteredIncidents} /><section className="section control-section" id="policy"><div className="control-grid"><PolicyPanel policy={policy} /><div className="infrastructure-panel"><img src={images.infrastructure} alt="Close-up of a high density circuit board" /><div className="infrastructure-panel__wash" /><div className="infrastructure-panel__copy"><div className="eyebrow"><span className="eyebrow__line" />Infrastructure / 04</div><h3>Built for the<br /><em>critical path.</em></h3><span>Live telemetry across the systems that matter.</span></div><Network size={20} /></div><SystemStatus connection={{ api: connection.api, ws: connection.api }} /></div></section><CapabilityStrip /><AuditPanel audit={audit} /></main>
    <footer className="footer"><div><a className="brand" href="#overview"><span className="brand__mark"><span /><span /><span /></span><span><strong>AEGISFLOW</strong><small>Cyber Defense Platform</small></span></a></div><span>{systemCopy}</span><span>© 2026 / defense by design</span></footer>
    {selected && <DetailPanel incident={selected} detail={detail} onClose={() => { setSelected(null); setDetail(null); }} />}
    {actionError && <div className="action-toast" role="alert"><CircleAlert size={16} /><span>{actionError}</span><button type="button" onClick={() => setActionError('')} aria-label="Dismiss message"><X size={15} /></button></div>}
    <IncidentAlert incident={liveIncident} countdown={countdown} actionBusy={actionBusy} onDecision={submitDecision} onOverride={submitOverride} onClose={() => setLiveIncident(null)} />
  </div>;
}

function App() {
  const [incidents, setIncidents] = useState([]);
  const [traffic, setTraffic] = useState([]);
  const [audit, setAudit] = useState([]);
  const [metrics, setMetrics] = useState(null);
  const [policy, setPolicy] = useState(null);
  const [selected, setSelected] = useState(null);
  const [detail, setDetail] = useState(null);
  const [liveIncident, setLiveIncident] = useState(null);
  const [countdown, setCountdown] = useState(null);
  const [actionBusy, setActionBusy] = useState(false);
  const [connection, setConnection] = useState({ api: false, ws: false });
  const [mobileMenu, setMobileMenu] = useState(false);
  const socketRef = useRef(null);
  const reconnectTimer = useRef(null);

  const fetchJson = useCallback(async (path) => {
    const response = await fetch(`${API_BASE}${path}`);
    if (!response.ok) throw new Error(`${path} ${response.status}`);
    return response.json();
  }, []);

  const loadData = useCallback(async () => {
    const requests = [
      ['incidents', '/api/incidents'], ['traffic', '/api/traffic/live'], ['audit', '/api/audit-log'], ['metrics', '/api/metrics'], ['policy', '/api/policy'],
    ];
    const results = await Promise.allSettled(requests.map(([, path]) => fetchJson(path)));
    const [incidentResult, trafficResult, auditResult, metricsResult, policyResult] = results;
    const apiWorked = results.some((result) => result.status === 'fulfilled');
    setConnection((current) => ({ ...current, api: apiWorked }));
    if (incidentResult.status === 'fulfilled') setIncidents(getArray(incidentResult.value, ['incidents', 'data']));
    if (trafficResult.status === 'fulfilled') setTraffic(getArray(trafficResult.value, ['traffic', 'data']));
    if (auditResult.status === 'fulfilled') setAudit(getArray(auditResult.value, ['events', 'audit', 'data']));
    if (metricsResult.status === 'fulfilled') setMetrics(metricsResult.value?.metrics || metricsResult.value);
    if (policyResult.status === 'fulfilled') setPolicy(policyResult.value?.policy || policyResult.value);
  }, [fetchJson]);

  const openDetail = useCallback(async (incident) => {
    setSelected(incident);
    setDetail(null);
    const id = incident.incident_id || incident.id;
    if (!id) return;
    try { const data = await fetchJson(`/api/incidents/${id}`); setDetail(data?.incident || data); } catch { setDetail(incident); }
  }, [fetchJson]);

  const mergeIncident = useCallback((incoming) => {
    if (!incoming) return;
    const next = incoming.incident || incoming;
    const id = next.incident_id || next.id;
    setIncidents((current) => id ? [next, ...current.filter((item) => (item.incident_id || item.id) !== id)] : [next, ...current]);
    setLiveIncident(next);
    setCountdown(next.countdown ?? next.countdown_seconds ?? null);
    openDetail(next);
  }, [openDetail]);

  const connectSocket = useCallback(() => {
    if (socketRef.current) socketRef.current.close();
    let socket;
    try { socket = new WebSocket(WS_URL); socketRef.current = socket; } catch { setConnection((current) => ({ ...current, ws: false })); return; }
    socket.onopen = () => setConnection((current) => ({ ...current, ws: true }));
    socket.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);
        const type = message.type || message.event;
        const payload = message.data || message.incident || message;
        if (type === 'new_incident') mergeIncident(payload);
        if (type === 'countdown_tick') setCountdown(payload.countdown ?? payload.remaining ?? payload.seconds ?? payload.value ?? null);
        if (type === 'state_change') {
          const updated = payload.incident || payload;
          setIncidents((current) => current.map((item) => (item.incident_id || item.id) === (updated.incident_id || updated.id) ? { ...item, ...updated } : item));
          setLiveIncident((current) => current ? { ...current, ...updated } : current);
        }
        if (type === 'verified') {
          const updated = payload.incident || payload;
          setLiveIncident((current) => current ? { ...current, ...updated, verified: true } : current);
          loadData();
        }
      } catch { /* Ignore malformed frames without crashing the command center. */ }
    };
    socket.onclose = () => { setConnection((current) => ({ ...current, ws: false })); reconnectTimer.current = window.setTimeout(connectSocket, 4500); };
    socket.onerror = () => setConnection((current) => ({ ...current, ws: false }));
  }, [loadData, mergeIncident]);

  useEffect(() => { loadData(); connectSocket(); return () => { if (reconnectTimer.current) window.clearTimeout(reconnectTimer.current); socketRef.current?.close(); }; }, [connectSocket, loadData]);

  const submitDecision = async (decision) => {
    const id = liveIncident?.incident_id || liveIncident?.id;
    if (!id) return;
    setActionBusy(true);
    try { await fetch(`${API_BASE}/api/incidents/${id}/decision`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ decision }) }); } finally { setActionBusy(false); }
  };

  const submitOverride = async () => {
    const id = liveIncident?.incident_id || liveIncident?.id;
    if (!id) return;
    setActionBusy(true);
    try { await fetch(`${API_BASE}/api/incidents/${id}/override`, { method: 'POST' }); } finally { setActionBusy(false); }
  };

  const systemCopy = useMemo(() => connection.ws ? 'Live defense plane connected' : 'Live connection lost · reconnecting', [connection.ws]);

  return <div className="app-shell">
    <header className="topbar"><a className="brand" href="#overview"><span className="brand__mark"><span /><span /><span /></span><span><strong>AEGISFLOW</strong><small>Cyber Defense Platform</small></span></a><nav className={mobileMenu ? 'nav nav--open' : 'nav'}>{['Overview', 'Incidents', 'Live Traffic', 'Attack Timeline', 'Audit & Transparency', 'Policy'].map((item) => <a href={`#${item === 'Overview' ? 'overview' : item === 'Incidents' ? 'incidents' : item === 'Live Traffic' ? 'traffic' : item === 'Attack Timeline' ? 'timeline' : item === 'Audit & Transparency' ? 'audit' : 'policy'}`} key={item} onClick={() => setMobileMenu(false)}>{item}</a>)}</nav><div className="topbar__tools"><IconButton label="Search"><Search size={17} /></IconButton><IconButton label="Notifications"><Bell size={17} /></IconButton><StatusMarker label={connection.ws ? 'Live' : 'Reconnecting'} tone={connection.ws ? 'green' : 'orange'} /><span className="avatar">AF</span></div><button className="mobile-menu" type="button" aria-label="Toggle navigation" onClick={() => setMobileMenu((value) => !value)}><Menu size={20} /></button></header>
    <main><Hero /><MetricBand metrics={metrics} /><SignalSection traffic={traffic} /><IncidentsSection incidents={incidents} onOpen={openDetail} /><Timeline incidents={incidents} /><section className="section control-section" id="policy"><div className="control-grid"><PolicyPanel policy={policy} /><div className="infrastructure-panel"><img src={images.infrastructure} alt="Close-up of a high density circuit board" /><div className="infrastructure-panel__wash" /><div className="infrastructure-panel__copy"><div className="eyebrow"><span className="eyebrow__line" />Infrastructure / 04</div><h3>Built for the<br /><em>critical path.</em></h3><span>Live telemetry across the systems that matter.</span></div><Network size={20} /></div><SystemStatus connection={connection} /></div></section><CapabilityStrip /><AuditPanel audit={audit} /></main>
    <footer className="footer"><div><a className="brand" href="#overview"><span className="brand__mark"><span /><span /><span /></span><span><strong>AEGISFLOW</strong><small>Cyber Defense Platform</small></span></a></div><span>{systemCopy}</span><span>© 2026 / defense by design</span></footer>
    {selected && <DetailPanel incident={selected} detail={detail} onClose={() => { setSelected(null); setDetail(null); }} />}
    <IncidentAlert incident={liveIncident} countdown={countdown} actionBusy={actionBusy} onDecision={submitDecision} onOverride={submitOverride} onClose={() => setLiveIncident(null)} />
  </div>;
}

createRoot(document.getElementById('root')).render(<React.StrictMode><IntegratedApp /></React.StrictMode>);
