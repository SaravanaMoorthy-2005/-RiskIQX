export interface IncidentSummary {
  rank: number;
  incident_id: string;
  title: string;
  status: string;
  priority_score: number;
  priority_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
  attack_confidence: number;
  data_confidence: number;
  affected_assets: string[];
  affected_users: string[];
  attack_types: string[];
  top_drivers: string[];
  created_at: string;
  sla_deadline?: string;
}

export interface FactorContribution {
  factor_name: string;
  raw_value: string;
  normalized_value: number;
  weight: number;
  contribution: number;
}

export interface ScoreBreakdown {
  final_score: number;
  priority_level: string;
  attack_confidence: number;
  data_confidence: number;
  missing_factors: string[];
  contributions: Record<string, FactorContribution>;
}

export interface IncidentDetailData extends IncidentSummary {
  mitre_techniques: string[];
  business_impact: number;
  data_sensitivity: number;
  related_alerts_count: number;
  explanation: string;
  attack_story: string;
  recommended_playbook: string;
  assigned_analyst?: string;
  score_breakdown: ScoreBreakdown;
  vulnerabilities: Array<{
    cve_id: string;
    cvss_score: number;
    known_exploited: boolean;
    description?: string;
  }>;
}

export interface PairwiseDelta {
  factor_name: string;
  inc_a_value: string;
  inc_b_value: string;
  inc_a_contribution: number;
  inc_b_contribution: number;
  contribution_diff: number;
  explanation: string;
}

export interface PairwiseExplanation {
  incident_a_id: string;
  incident_a_title: string;
  incident_a_score: number;
  incident_b_id: string;
  incident_b_title: string;
  incident_b_score: number;
  score_gap: number;
  top_winning_factors: string[];
  factor_deltas: PairwiseDelta[];
  summary_narrative: string;
}

export interface TimelineItem {
  event_id: string;
  timestamp: string;
  source: string;
  event_type: string;
  category: string;
  severity: number;
  host?: string;
  user?: string;
  action_summary: string;
}

export interface PostureMetrics {
  defcon_level: string;
  defcon_badge: 'CRITICAL' | 'HIGH' | 'NOMINAL';
  mttd_minutes: number;
  mttr_minutes: number;
  zero_trust_coverage_percent: number;
  active_playbook_coverage_percent: number;
  attack_surface_exposure_index: number;
  telemetry_ingest_rate_eps: number;
}

export interface MitreMatrixItem {
  technique_id: string;
  technique_name: string;
  tactic: string;
  count: number;
  raw: string;
}

export interface AiThreatRecommendation {
  id: string;
  urgency: 'IMMEDIATE' | 'TACTICAL' | 'STRATEGIC';
  title: string;
  threat_vector: string;
  target_scope: string;
  risk_reduction_points: number;
  mitre_technique: string;
  confidence_score: number;
  implementation_effort: string;
  summary: string;
  mitigation_steps: string[];
  automation_script: string;
}

export interface AnalyticsSummary {
  metrics: {
    total_telemetry_events: number;
    duplicate_events_filtered: number;
    deduplication_rate_percent: number;
    total_detections_generated: number;
    total_incidents: number;
    open_incidents: number;
    critical_incidents: number;
    high_incidents: number;
    medium_incidents: number;
    low_incidents: number;
    average_risk_score: number;
    false_positive_rate_percent: number;
    confirmed_incident_rate_percent: number;
  };
  posture_metrics?: PostureMetrics;
  mitre_matrix?: MitreMatrixItem[];
  ai_recommendations?: AiThreatRecommendation[];
  priority_distribution: Array<{ level: string; count: number; color: string }>;
  category_distribution: Array<{ category: string; count: number }>;
  top_noisy_rules: Array<{ rule: string; triggers: number }>;
  recent_audit_logs: Array<{
    timestamp: string;
    actor: string;
    action: string;
    entity: string;
    details: any;
  }>;
}
