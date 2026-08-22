import { initializeDatabase, saveSecurityEventToDb, checkDatabaseHealth } from './src/services/postgres.js';

async function test() {
  await initializeDatabase();
  console.log("Health:", await checkDatabaseHealth());
  const event = {
    id: 'evt_test123',
    timestamp: Date.now(),
    flow_id: 'test_flow',
    sourceIp: '192.168.1.100',
    destinationIp: '192.168.1.1',
    protocol: 'TCP',
    attackType: 'BENIGN',
    realPrediction: {
      prediction: 'BENIGN',
      probabilities: [0.9, 0.1],
      lstm: { anomaly_score: 0.1 },
      risk_score: 0.2,
      dqn: {
        action: 'ALLOW',
        q_values: { ALLOW: 0.9, ALERT: 0.2, BLOCK: 0.1 }
      },
      shap: {
        features: [ { feature: 'test_feat', shap_value: 0.5, importance: 0.8 } ]
      }
    },
    realFeatures: { test_feat: 100 },
    actionExecuted: 'ALLOW',
    isBlocked: false,
    alertDispatched: false
  };
  await saveSecurityEventToDb(event);
  console.log("Event saved!");
  process.exit(0);
}

test();
