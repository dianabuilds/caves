import express, { type Request, type Response, type NextFunction } from 'express';
import payload from 'payload';
import cookieParser from 'cookie-parser';
import { randomBytes } from 'crypto';
import { SiweMessage } from 'siwe';
import jwt from 'jsonwebtoken';
import config from '../payload.config';
import { env } from './env';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { Pool } from 'pg';
import sgMail from '@sendgrid/mail';
import { createClient } from 'redis';
import archiver from 'archiver';

sgMail.setApiKey(env.sendgridApiKey);

const pool = new Pool({
  connectionString: env.databaseUrl,
});

const ENCRYPTION_KEY = env.dbEncryptionKey;

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
    ip TEXT,
    ua TEXT,
    ts TIMESTAMPTZ DEFAULT now()
  )`
);

const logUserEvent = async (
  req: Request,
  userId: string | null,
  action: string,
) => {
  const ip = req.ip;
  const ua = req.headers['user-agent'] || '';
  await pool.query(
    'INSERT INTO user_events (user_id, action, ip, ua) VALUES ($1, $2, $3, $4)',
    [userId, action, ip, ua],
  );
};

const app = express();
app.use(express.json());
app.use(cookieParser());

const staticDir = path.join(__dirname, 'public');
app.use(express.static(staticDir));
app.get('/privacy', (_req, res) => {
  res.sendFile(path.join(staticDir, 'privacy.html'));
});

const redis = createClient({ url: env.redisUrl });
redis.connect().catch(() => {});

const RATE_LIMIT = 20;
const WINDOW_SECONDS = 15 * 60;

const authRateLimiter = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const ip = req.ip;
  try {
    const key = `rl:${ip}`;
    const count = await redis.incr(key);
    if (count === 1) await redis.expire(key, WINDOW_SECONDS);
    if (count > RATE_LIMIT) {
      return res.status(429).json({ error: 'Too many requests' });
    }
  } catch {
    // ignore redis errors
  }
  next();
};

app.use('/api/auth', authRateLimiter);

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
    const decoded = jwt.verify(token, env.jwtSecret) as {
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
      const decoded = jwt.verify(token, env.jwtSecret) as {
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

app.post('/api/auth/register', async (req: Request, res: Response) => {
  const { walletAddress, username, passwordHash, email } = req.body;
  if (typeof walletAddress !== 'string') {
    return res.status(400).json({ error: 'Invalid request' });
  }
  try {
    const user = await payload.create({
      collection: 'users',
      data: { walletAddress, username, passwordHash, email },
    });
    const token = jwt.sign(
      { address: walletAddress },
      env.jwtSecret,
      { expiresIn: '15m' },
    );
    await logUserEvent(req, String(user.id), 'register');
    res.json({ token, user: sanitizeUser(user, true) });
  } catch {
    res.status(400).json({ error: 'Registration failed' });
  }
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
      env.jwtSecret,
      { expiresIn: '15m' }
    );
    res.cookie('sid', sessionId, { httpOnly: true, secure: true, sameSite: 'lax' });
    await logUserEvent(req, userId, 'login');
    res.json({ token });
  } catch (err) {
    res.status(400).json({ error: 'Invalid login' });
  }
});

app.post('/api/auth/login-password', async (req: Request, res: Response) => {
  const { email, passwordHash } = req.body;
  if (typeof email !== 'string' || typeof passwordHash !== 'string') {
    return res.status(400).json({ error: 'Invalid request' });
  }
  try {
    const encryptedEmail = await encryptValue(email);
    const { docs } = await payload.find({
      collection: 'users',
      where: { email: { equals: encryptedEmail } },
      limit: 1,
    });
    if (!docs.length || docs[0].passwordHash !== passwordHash) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const user = docs[0];
    const token = jwt.sign(
      { address: user.walletAddress },
      env.jwtSecret,
      { expiresIn: '15m' },
    );
    await logUserEvent(req, String(user.id), 'login_password');
    res.json({ token, user: sanitizeUser(user, true) });
  } catch {
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
      await logUserEvent(req, session.userId, 'logout');
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
    await logUserEvent(req, req.user.id, 'change_password');
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
          from: env.sendgridFrom,
          subject: 'Password Reset',
          text: `Your reset token: ${token}`,
        });
      } catch {
        // ignore email errors
      }
      await logUserEvent(req, userId, 'forgot_password');
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
    await logUserEvent(req, entry.userId, 'reset_password');
    res.status(204).send();
  } catch {
    res.status(400).json({ error: 'Invalid token' });
  }
});

app.get(
  '/api/users/me',
  authenticate,
  async (req: AuthenticatedRequest, res: Response) => {
    await logUserEvent(req, req.user.id, 'get_me');
    res.json(sanitizeUser(req.user, true));
  },
);

app.get(
  '/api/users/me/export',
  authenticate,
  async (req: AuthenticatedRequest, res: Response) => {
    await logUserEvent(req, req.user.id, 'export_me');
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="export.zip"');
    const archive = archiver('zip');
    archive.pipe(res);
    const userData = sanitizeUser(req.user, true);
    archive.append(JSON.stringify(userData, null, 2), { name: 'user.json' });
    if (userData.avatar) {
      const filePath = path.join(__dirname, '..', userData.avatar);
      if (fs.existsSync(filePath)) {
        archive.file(filePath, { name: path.basename(filePath) });
      }
    }
    await archive.finalize();
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
    await logUserEvent(req, req.user.id, 'patch_me');
    res.json(sanitizeUser(updated, true));
  },
);

app.delete(
  '/api/users/me',
  authenticate,
  async (req: AuthenticatedRequest, res: Response) => {
    await softDeleteUser(req.user.id);
    invalidateUserSessions(req.user.id);
    await logUserEvent(req, req.user.id, 'delete_me');
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
      await logUserEvent(req, req.user?.id || null, `get_user_${req.params.id}`);
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
