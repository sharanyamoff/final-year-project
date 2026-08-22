import pg from 'pg';
import dotenv from 'dotenv';
import { ProcessedSecurityEvent } from '../types';

dotenv.config();

const { Pool } = pg;

const pool = new Pool({
  host: process.env.PGHOST || '127.0.0.1',
  port: parseInt(process.env.PGPORT || '5432'),
  database: process.env.PGDATABASE || 'xrl_idars',
  user: process.env.PGUSER || 'postgres',
  password: process.env.PGPASSWORD || '',
});

export async function initializeDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS security_events (
        id VARCHAR(50) PRIMARY KEY,
        timestamp BIGINT NOT NULL,
        flow_id VARCHAR(100),
        source_ip VARCHAR(50),
        destination_ip VARCHAR(50),
        protocol VARCHAR(20),
        attack_type VARCHAR(50),
        risk_score FLOAT,
        rf_probability FLOAT,
        lstm_anomaly_score FLOAT,
        dqn_action VARCHAR(20),
        q_allow FLOAT,
        q_alert FLOAT,
        q_block FLOAT,
        action_executed VARCHAR(20),
        is_blocked BOOLEAN,
        alert_dispatched BOOLEAN,
        raw_features JSONB,
        raw_prediction JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS event_shap_features (
        id SERIAL PRIMARY KEY,
        event_id VARCHAR(50) REFERENCES security_events(id) ON DELETE CASCADE,
        feature VARCHAR(100) NOT NULL,
        shap_value FLOAT,
        importance FLOAT
      );
    `);

    // Create Indexes
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_sec_events_timestamp ON security_events(timestamp);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_sec_events_source_ip ON security_events(source_ip);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_sec_events_attack_type ON security_events(attack_type);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_sec_events_risk_score ON security_events(risk_score);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_sec_events_dqn_action ON security_events(dqn_action);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_sec_events_flow_id ON security_events(flow_id);`);

    console.log('[PostgreSQL] Schema initialized');
  } catch (error) {
    console.error('[PostgreSQL] Schema initialization failed:', error);
  }
}

export async function saveSecurityEventToDb(event: ProcessedSecurityEvent) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const prediction = event.realPrediction;
    const rf_prob = prediction?.probabilities ? Math.max(...prediction.probabilities) : null;
    const lstm_score = prediction?.lstm?.anomaly_score ?? null;
    const flow_id = prediction?.flow_id || 'unknown';
    const risk_score = prediction?.risk_score ?? null;
    const dqn = prediction?.dqn;
    const q_allow = dqn?.q_values?.ALLOW ?? null;
    const q_alert = dqn?.q_values?.ALERT ?? null;
    const q_block = dqn?.q_values?.BLOCK ?? null;
    const dqn_action = dqn?.action ?? null;

    await client.query(
      `INSERT INTO security_events (
        id, timestamp, flow_id, source_ip, destination_ip, protocol, attack_type, 
        risk_score, rf_probability, lstm_anomaly_score, dqn_action, q_allow, 
        q_alert, q_block, action_executed, is_blocked, alert_dispatched, 
        raw_features, raw_prediction
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)`,
      [
        event.id,
        event.timestamp,
        flow_id,
        event.sourceIp,
        event.destinationIp,
        event.protocol,
        event.attackType,
        risk_score,
        rf_prob,
        lstm_score,
        dqn_action,
        q_allow,
        q_alert,
        q_block,
        event.actionExecuted,
        event.isBlocked,
        event.alertDispatched,
        JSON.stringify(event.realFeatures || {}),
        JSON.stringify(prediction || {})
      ]
    );

    const shapFeatures = prediction?.shap?.features || [];
    if (shapFeatures.length > 0) {
      for (const shap of shapFeatures) {
        await client.query(
          `INSERT INTO event_shap_features (event_id, feature, shap_value, importance)
           VALUES ($1, $2, $3, $4)`,
          [event.id, shap.feature, shap.shap_value, shap.importance]
        );
      }
    }

    await client.query('COMMIT');
    console.log(`[PostgreSQL] Security event saved: ${event.id}`);
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('[PostgreSQL] Failed to save security event:', error);
    throw error;
  } finally {
    client.release();
  }
}

export async function checkDatabaseHealth() {
  try {
    const res = await pool.query('SELECT 1');
    return res.rowCount !== null;
  } catch (err) {
    console.error('[PostgreSQL] Health check failed:', err);
    return false;
  }
}
