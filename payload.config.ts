import { buildConfig } from 'payload/config';
import dotenv from 'dotenv';
import { Pool } from 'pg';

dotenv.config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

export default buildConfig({
  serverURL: 'http://localhost:3000',
  globals: [],
  db: {
    pool,
  },
  secret: process.env.PAYLOAD_SECRET || '',
  expressSession: {
    secret: process.env.SESSION_SECRET || '',
  },
});
