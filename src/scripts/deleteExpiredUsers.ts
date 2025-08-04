import { Pool } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
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
