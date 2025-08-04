import express, { type Request, type Response, type NextFunction } from 'express';
import payload from 'payload';
import cookieParser from 'cookie-parser';
import { randomBytes } from 'crypto';
import { SiweMessage } from 'siwe';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import config from '../payload.config';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { Pool } from 'pg';
import sgMail from '@sendgrid/mail';

dotenv.config();
sgMail.setApiKey(process.env.SENDGRID_API_KEY || '');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

const ENCRYPTION_KEY = process.env.DB_ENCRYPTION_KEY || 'default_secret';

const encryptValue = async (value: string): Promise<string> => {
  const res = await pool.query(
    "SELECT encode(pgp_sym_encrypt($1, $2), 'base64') AS enc",
    [value, ENCRYPTION_KEY],
  );
  return res.rows[0]?.enc as string;
};

pool.query(
  `CREATE TABLE IF NOT EXISTS user_events (
    id SERIAL PRIMARY KEY,
    user_id TEXT,
    action TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
  )`
);

const logUserEvent = async (userId: string | null, action: string) => {
  await pool.query('INSERT INTO user_events (user_id, action) VALUES ($1, $2)', [userId, action]);
};

const app = express();
app.use(express.json());
app.use(cookieParser());

const uploadDir = path.join(__dirname, '../uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}
const upload = multer({ dest: uploadDir });

interface AuthenticatedRequest extends Request {
  user?: any;
}

const authenticate = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction,
) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'jwt_secret') as {
      address: string;
    };
    const { docs } = await payload.find({
      collection: 'users',
      where: { walletAddress: { equals: decoded.address } },
      limit: 1,
    });
    if (!docs.length) return res.status(401).json({ error: 'User not found' });
    req.user = docs[0];
    next();
  } catch {
    res.status(401).json({ error: 'Unauthorized' });
  }
};

const optionalAuthenticate = async (
  req: AuthenticatedRequest,
  _res: Response,
  next: NextFunction,
) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(' ')[1];
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'jwt_secret') as {
        address: string;
      };
      const { docs } = await payload.find({
        collection: 'users',
        where: { walletAddress: { equals: decoded.address } },
        limit: 1,
      });
      if (docs.length) req.user = docs[0];
    } catch {
      // ignore invalid token
    }
  }
  next();
};

const sanitizeUser = (user: any, isSelf: boolean) => {
  const { passwordHash, ...rest } = user;
  if (isSelf) return rest;
  const {
    email,
    walletAddress,
    settings,
    subscriptionUntil,
    role,
    premiumTier,
    ...publicData
  } = rest;
  return publicData;
};

const nonces = new Set<string>();
const sessions = new Map<string, { refreshToken: string; userId: string }>();
const userSessions = new Map<string, Set<string>>();
const passwordResetTokens = new Map<
  string,
  { userId: string; expires: number }
>();

const invalidateUserSessions = (userId: string) => {
  const sids = userSessions.get(userId);
  if (sids) {
    for (const sid of sids) {
      sessions.delete(sid);
    }
    userSessions.delete(userId);
  }
};

const softDeleteUser = async (userId: string) => {
  await payload.update({
    collection: 'users',
    id: userId,
    data: {
      deletedAt: new Date().toISOString(),
      email: null,
      passwordHash: null,
      settings: null,
      role: null,
      premiumTier: null,
      subscriptionUntil: null,
    },
  });
};

app.get('/api/auth/nonce', (_req: Request, res: Response) => {
  const nonce = randomBytes(16).toString('hex');
  nonces.add(nonce);
  res.json({ nonce });
});

app.post('/api/auth/login', async (req: Request, res: Response) => {
  try {
    const { message, signature } = req.body;
    const siweMessage = new SiweMessage(message);
    const { data } = await siweMessage.verify({ signature });
    if (!nonces.has(data.nonce)) {
      return res.status(400).json({ error: 'Invalid nonce' });
    }
    nonces.delete(data.nonce);
    const { docs } = await payload.find({
      collection: 'users',
      where: { walletAddress: { equals: data.address } },
      limit: 1,
    });
    if (!docs.length) {
      return res.status(401).json({ error: 'User not found' });
    }
    const user = docs[0];
    const userId = String(user.id);
    const sessionId = randomBytes(16).toString('hex');
    const refreshToken = randomBytes(32).toString('hex');
    sessions.set(sessionId, { refreshToken, userId });
    if (!userSessions.has(userId)) userSessions.set(userId, new Set());
    userSessions.get(userId)!.add(sessionId);
    const token = jwt.sign(
      { address: data.address },
      process.env.JWT_SECRET || 'jwt_secret',
      { expiresIn: '15m' }
    );
    res.cookie('sid', sessionId, { httpOnly: true, secure: true, sameSite: 'lax' });
    await logUserEvent(userId, 'login');
    res.json({ token });
  } catch (err) {
    res.status(400).json({ error: 'Invalid login' });
  }
});

app.post('/api/auth/logout', async (req: Request, res: Response) => {
  const sid = req.cookies?.sid as string | undefined;
  if (sid) {
    const session = sessions.get(sid);
    if (session) {
      sessions.delete(sid);
      const sids = userSessions.get(session.userId);
      if (sids) {
        sids.delete(sid);
        if (!sids.size) userSessions.delete(session.userId);
      }
      await logUserEvent(session.userId, 'logout');
    }
    res.clearCookie('sid');
  }
  res.status(204).send();
});

app.post(
  '/api/auth/change-password',
  authenticate,
  async (req: AuthenticatedRequest, res: Response) => {
    const { currentHash, newHash } = req.body;
    if (typeof currentHash !== 'string' || typeof newHash !== 'string') {
      return res.status(400).json({ error: 'Invalid request' });
    }
    if (req.user.passwordHash !== currentHash) {
      return res.status(400).json({ error: 'Incorrect password' });
    }
    await payload.update({
      collection: 'users',
      id: req.user.id,
      data: { passwordHash: newHash },
    });
    await logUserEvent(req.user.id, 'change_password');
    res.status(204).send();
  },
);

app.post('/api/auth/forgot', async (req: Request, res: Response) => {
  const { email } = req.body;
  if (typeof email !== 'string') {
    return res.status(400).json({ error: 'Invalid request' });
  }
  try {
    const encryptedEmail = await encryptValue(email);
    const { docs } = await payload.find({
      collection: 'users',
      where: { email: { equals: encryptedEmail } },
      limit: 1,
    });
    if (docs.length) {
      const user = docs[0];
      const userId = String(user.id);
      const token = randomBytes(32).toString('hex');
      passwordResetTokens.set(token, {
        userId,
        expires: Date.now() + 3600_000,
      });
      try {
        await sgMail.send({
          to: user.email,
          from: process.env.SENDGRID_FROM || 'no-reply@example.com',
          subject: 'Password Reset',
          text: `Your reset token: ${token}`,
        });
      } catch {
        // ignore email errors
      }
      await logUserEvent(userId, 'forgot_password');
    }
  } catch {
    // ignore lookup errors
  }
  res.json({ ok: true });
});

app.post('/api/auth/reset', async (req: Request, res: Response) => {
  const { token, newHash } = req.body;
  if (typeof token !== 'string' || typeof newHash !== 'string') {
    return res.status(400).json({ error: 'Invalid request' });
  }
  const entry = passwordResetTokens.get(token);
  if (!entry || entry.expires < Date.now()) {
    return res.status(400).json({ error: 'Invalid token' });
  }
  try {
    await payload.update({
      collection: 'users',
      id: entry.userId,
      data: { passwordHash: newHash },
    });
    passwordResetTokens.delete(token);
    invalidateUserSessions(entry.userId);
    await logUserEvent(entry.userId, 'reset_password');
    res.status(204).send();
  } catch {
    res.status(400).json({ error: 'Invalid token' });
  }
});

app.get(
  '/api/users/me',
  authenticate,
  async (req: AuthenticatedRequest, res: Response) => {
    await logUserEvent(req.user.id, 'get_me');
    res.json(sanitizeUser(req.user, true));
  },
);

app.patch(
  '/api/users/me',
  authenticate,
  upload.single('avatar'),
  async (req: AuthenticatedRequest, res: Response) => {
    const updates: any = { ...req.body };
    if (req.file) {
      updates.avatar = `/uploads/${req.file.filename}`;
    }
    if (updates.username && updates.username !== req.user.username) {
      const { docs } = await payload.find({
        collection: 'users',
        where: { username: { equals: updates.username } },
        limit: 1,
      });
      if (docs.length && docs[0].id !== req.user.id) {
        return res.status(400).json({ error: 'Username already taken' });
      }
    }
    const updated = await payload.update({
      collection: 'users',
      id: req.user.id,
      data: updates,
    });
    await logUserEvent(req.user.id, 'patch_me');
    res.json(sanitizeUser(updated, true));
  },
);

app.delete(
  '/api/users/me',
  authenticate,
  async (req: AuthenticatedRequest, res: Response) => {
    await softDeleteUser(req.user.id);
    invalidateUserSessions(req.user.id);
    await logUserEvent(req.user.id, 'delete_me');
    res.status(204).send();
  },
);

app.get(
  '/api/users/:id',
  optionalAuthenticate,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const user = await payload.findByID({
        collection: 'users',
        id: req.params.id,
      });
      const isSelf = req.user && req.user.id === user.id;
      await logUserEvent(req.user?.id || null, `get_user_${req.params.id}`);
      res.json(sanitizeUser(user, isSelf));
    } catch {
      res.status(404).json({ error: 'User not found' });
    }
  },
);

const start = async () => {
  await payload.init({ config });

  app.listen(3000, () => {
    payload.logger.info('Server started at http://localhost:3000');
  });
};

start();
