import dotenv from 'dotenv';

dotenv.config();

export const env = {
  databaseUrl: process.env.DATABASE_URL || '',
  jwtSecret: process.env.JWT_SECRET || 'jwt_secret',
  sendgridApiKey: process.env.SENDGRID_API_KEY || '',
  sendgridFrom: process.env.SENDGRID_FROM || 'no-reply@example.com',
  redisUrl: process.env.REDIS_URL || '',
  dbEncryptionKey: process.env.DB_ENCRYPTION_KEY || 'default_secret',
  payloadSecret: process.env.PAYLOAD_SECRET || '',
  sessionSecret: process.env.SESSION_SECRET || '',
};
