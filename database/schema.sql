-- Cybersecurity Threat Detector Database Schema

-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Network Traffic Table
CREATE TABLE IF NOT EXISTS network_traffic (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    duration FLOAT NOT NULL,
    protocol_type VARCHAR(10) NOT NULL,
    service VARCHAR(20) NOT NULL,
    flag VARCHAR(10) NOT NULL,
    src_bytes INTEGER NOT NULL,
    dst_bytes INTEGER NOT NULL,
    land INTEGER NOT NULL,
    wrong_fragment INTEGER NOT NULL,
    urgent INTEGER NOT NULL,
    hot INTEGER NOT NULL,
    num_failed_logins INTEGER NOT NULL,
    logged_in INTEGER NOT NULL,
    num_compromised INTEGER NOT NULL,
    root_shell INTEGER NOT NULL,
    su_attempted INTEGER NOT NULL,
    num_root INTEGER NOT NULL,
    num_file_creations INTEGER NOT NULL,
    num_shells INTEGER NOT NULL,
    num_access_files INTEGER NOT NULL,
    num_outbound_cmds INTEGER NOT NULL,
    is_host_login INTEGER NOT NULL,
    is_guest_login INTEGER NOT NULL,
    count INTEGER NOT NULL,
    srv_count INTEGER NOT NULL,
    serror_rate FLOAT NOT NULL,
    srv_serror_rate FLOAT NOT NULL,
    rerror_rate FLOAT NOT NULL,
    srv_rerror_rate FLOAT NOT NULL,
    same_srv_rate FLOAT NOT NULL,
    diff_srv_rate FLOAT NOT NULL,
    srv_diff_host_rate FLOAT NOT NULL,
    dst_host_count INTEGER NOT NULL,
    dst_host_srv_count INTEGER NOT NULL,
    dst_host_same_srv_rate FLOAT NOT NULL,
    dst_host_diff_srv_rate FLOAT NOT NULL,
    dst_host_same_src_port_rate FLOAT NOT NULL,
    dst_host_srv_diff_host_rate FLOAT NOT NULL,
    dst_host_serror_rate FLOAT NOT NULL,
    dst_host_srv_serror_rate FLOAT NOT NULL,
    dst_host_rerror_rate FLOAT NOT NULL,
    dst_host_srv_rerror_rate FLOAT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT check_land CHECK (land IN (0, 1)),
    CONSTRAINT check_logged_in CHECK (logged_in IN (0, 1))
);

-- Threat Predictions Table
CREATE TABLE IF NOT EXISTS threat_predictions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    traffic_id UUID REFERENCES network_traffic(id) ON DELETE CASCADE,
    prediction VARCHAR(20) NOT NULL, -- 'normal' or 'malicious'
    confidence FLOAT NOT NULL,
    threat_type VARCHAR(50), -- 'DoS', 'Probe', 'R2L', 'U2R', NULL for normal
    model_version VARCHAR(20) DEFAULT 'v1.0',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT check_prediction CHECK (prediction IN ('normal', 'malicious')),
    CONSTRAINT check_confidence CHECK (confidence >= 0 AND confidence <= 1)
);

-- Alerts Table
CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    prediction_id UUID REFERENCES threat_predictions(id) ON DELETE CASCADE,
    severity VARCHAR(20) NOT NULL, -- 'low', 'medium', 'high', 'critical'
    status VARCHAR(20) DEFAULT 'new', -- 'new', 'acknowledged', 'resolved', 'false_positive'
    description TEXT,
    source_ip VARCHAR(45),
    destination_ip VARCHAR(45),
    acknowledged_at TIMESTAMP,
    acknowledged_by VARCHAR(100),
    resolved_at TIMESTAMP,
    resolved_by VARCHAR(100),
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT check_severity CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    CONSTRAINT check_status CHECK (status IN ('new', 'acknowledged', 'resolved', 'false_positive'))
);

-- System Metrics Table
CREATE TABLE IF NOT EXISTS system_metrics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    metric_type VARCHAR(50) NOT NULL, -- 'prediction_count', 'threat_count', 'latency', etc.
    metric_value FLOAT NOT NULL,
    metric_unit VARCHAR(20), -- 'count', 'ms', 'percentage', etc.
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- API Keys Table (for authentication)
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key_hash VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP,
    expires_at TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_traffic_created_at ON network_traffic(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_predictions_traffic_id ON threat_predictions(traffic_id);
CREATE INDEX IF NOT EXISTS idx_predictions_created_at ON threat_predictions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_predictions_prediction ON threat_predictions(prediction);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_metrics_type_created ON system_metrics(metric_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger for alerts table
CREATE TRIGGER update_alerts_updated_at BEFORE UPDATE ON alerts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insert sample API key for development (key: dev-api-key-12345)
-- Hash is just for demo - in production use proper bcrypt
INSERT INTO api_keys (key_hash, name, description) 
VALUES ('dev-api-key-12345', 'Development Key', 'Default API key for local development')
ON CONFLICT (key_hash) DO NOTHING;

-- Sample view for threat statistics
CREATE OR REPLACE VIEW threat_stats AS
SELECT 
    DATE(tp.created_at) as date,
    tp.prediction,
    tp.threat_type,
    COUNT(*) as count,
    AVG(tp.confidence) as avg_confidence
FROM threat_predictions tp
WHERE tp.created_at >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY DATE(tp.created_at), tp.prediction, tp.threat_type
ORDER BY date DESC;

-- Sample view for alert summary
CREATE OR REPLACE VIEW alert_summary AS
SELECT 
    a.severity,
    a.status,
    COUNT(*) as count,
    MAX(a.created_at) as last_alert_time
FROM alerts a
WHERE a.created_at >= CURRENT_DATE - INTERVAL '7 days'
GROUP BY a.severity, a.status;