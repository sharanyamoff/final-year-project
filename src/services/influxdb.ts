import Influx from 'influx';

const influx = new Influx.InfluxDB({
  host: process.env.INFLUX_HOST || '127.0.0.1',
  port: Number(process.env.INFLUX_PORT || 8086),
  database: process.env.INFLUX_DATABASE || 'xrl_idars',
});

export async function initializeInfluxDB(): Promise<void> {
  const databases = await influx.getDatabaseNames();

  if (!databases.includes('xrl_idars')) {
    await influx.createDatabase('xrl_idars');
    console.log('[InfluxDB] Database xrl_idars created');
  }

  console.log('[InfluxDB] Connected to xrl_idars');
}

export async function saveTelemetry(data: {
  packetsPerSec: number;
  riskScore: number;
  attacksCount: number;
  blockedCount: number;
  normalCount: number;
}): Promise<void> {
  await influx.writePoints([
    {
      measurement: 'network_telemetry',
      fields: {
        packets_per_sec: Number(data.packetsPerSec),
        risk_score: Number(data.riskScore),
        attacks_count: Number(data.attacksCount),
        blocked_count: Number(data.blockedCount),
        normal_count: Number(data.normalCount),
      },
    },
  ]);
}

export default influx;
