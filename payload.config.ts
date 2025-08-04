import { buildConfig } from 'payload/config';
import dotenv from 'dotenv';
import { Pool } from 'pg';
import Users from './src/collections/Users';

dotenv.config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Ensure pgcrypto extension for field-level encryption
pool.query('CREATE EXTENSION IF NOT EXISTS pgcrypto');

export default buildConfig({
  serverURL: 'http://localhost:3000',
  collections: [Users],
  globals: [],
  db: {
    pool,
  },
  secret: process.env.PAYLOAD_SECRET || '',
  expressSession: {
    secret: process.env.SESSION_SECRET || '',
  },
});
