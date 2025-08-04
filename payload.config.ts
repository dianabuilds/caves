import { buildConfig } from 'payload/config';
import { Pool } from 'pg';
import Users from './src/collections/Users';
import { env } from './src/env';

const pool = new Pool({
  connectionString: env.databaseUrl,
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
  secret: env.payloadSecret,
  expressSession: {
    secret: env.sessionSecret,
  },
});
