import { Pool } from 'pg';
import { env } from '../env';

const pool = new Pool({
  connectionString: env.databaseUrl,
});

const run = async () => {
  await pool.query(
    'DELETE FROM users WHERE "deletedAt" IS NOT NULL AND "deletedAt" < NOW() - INTERVAL \'30 days\''
  );
  await pool.end();
};

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
