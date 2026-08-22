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

export default influx;
