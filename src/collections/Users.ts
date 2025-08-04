import type { CollectionConfig, FieldHook } from 'payload';
import { Pool } from 'pg';
import { randomUUID } from 'crypto';
import { env } from '../env';

const pool = new Pool({
  connectionString: env.databaseUrl,
});

const ENCRYPTION_KEY = env.dbEncryptionKey;

const encrypt: FieldHook = async ({ value }: { value?: string }) => {
  if (typeof value !== 'string') return value;
  const res = await pool.query(
    "SELECT encode(pgp_sym_encrypt($1, $2), 'base64') AS enc",
    [value, ENCRYPTION_KEY],
  );
  return res.rows[0]?.enc as string;
};

const decrypt: FieldHook = async ({ value }: { value?: string }) => {
  if (typeof value !== 'string') return value;
  const res = await pool.query(
    "SELECT pgp_sym_decrypt(decode($1, 'base64'), $2) AS dec",
    [value, ENCRYPTION_KEY],
  );
  return res.rows[0]?.dec as string;
};

const bcryptRegex = /^\$2[aby]\$\d{2}\$[./0-9A-Za-z]{53}$/;
const argon2idRegex = /^\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+=*\$[A-Za-z0-9+/]+=*$/;

const Users: CollectionConfig = {
  slug: 'users',
  admin: { useAsTitle: 'username' },
  timestamps: true,
  fields: [
    {
      name: 'id',
      type: 'text',
      required: true,
      unique: true,
      index: true,
      defaultValue: () => randomUUID(),
    },
    {
      name: 'walletAddress',
      type: 'text',
      required: true,
      unique: true,
      index: true,
      validate: (val: unknown) =>
        typeof val === 'string' && /^0x[a-fA-F0-9]{40}$/.test(val)
          ? true
          : 'Invalid wallet address format',
    },
    {
      name: 'email',
      type: 'text',
      required: true,
      unique: true,
      index: true,
      validate: (val: unknown) =>
        typeof val === 'string' && /^\S+@\S+\.\S+$/.test(val)
          ? true
          : 'Invalid email format',
      hooks: {
        beforeChange: [encrypt],
        afterRead: [decrypt],
      },
    },
    {
      name: 'passwordHash',
      type: 'text',
      required: true,
      validate: (val: unknown) =>
        typeof val === 'string' &&
        (bcryptRegex.test(val) || argon2idRegex.test(val))
          ? true
          : 'Password hash must be bcrypt or argon2id',
      hooks: {
        beforeChange: [encrypt],
        afterRead: [decrypt],
      },
    },
    {
      name: 'username',
      type: 'text',
      required: true,
      unique: true,
      index: true,
      validate: (val: unknown) =>
        typeof val === 'string' && val.length >= 3 && val.length <= 30
          ? true
          : 'Username must be 3-30 characters',
    },
    {
      name: 'avatar',
      type: 'text',
    },
    {
      name: 'bio',
      type: 'textarea',
    },
    {
      name: 'role',
      type: 'select',
      options: [
        { label: 'User', value: 'user' },
        { label: 'Admin', value: 'admin' },
      ],
      defaultValue: 'user',
    },
    {
      name: 'premiumTier',
      type: 'number',
    },
    {
      name: 'subscriptionUntil',
      type: 'date',
    },
    {
      name: 'settings',
      type: 'json',
    },
    {
      name: 'deletedAt',
      type: 'date',
    },
  ],
};

export default Users;
