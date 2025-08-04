import express, { type Request, type Response } from 'express';
import payload from 'payload';
import cookieParser from 'cookie-parser';
import { randomBytes } from 'crypto';
import { SiweMessage } from 'siwe';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import config from '../payload.config';

dotenv.config();

const app = express();
app.use(express.json());
app.use(cookieParser());

const nonces = new Set<string>();
const sessions = new Map<string, string>();

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
    const sessionId = randomBytes(16).toString('hex');
    const refreshToken = randomBytes(32).toString('hex');
    sessions.set(sessionId, refreshToken);
    const token = jwt.sign(
      { address: data.address },
      process.env.JWT_SECRET || 'jwt_secret',
      { expiresIn: '15m' }
    );
    res.cookie('sid', sessionId, { httpOnly: true, secure: true, sameSite: 'lax' });
    res.json({ token });
  } catch (err) {
    res.status(400).json({ error: 'Invalid login' });
  }
});

app.post('/api/auth/logout', (req: Request, res: Response) => {
  const sid = req.cookies?.sid as string | undefined;
  if (sid) {
    sessions.delete(sid);
    res.clearCookie('sid');
  }
  res.status(204).send();
});

const start = async () => {
  await payload.init({ config });

  app.listen(3000, () => {
    payload.logger.info('Server started at http://localhost:3000');
  });
};

start();
