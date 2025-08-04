import { test, expect } from '@playwright/test';
import { spawn } from 'child_process';
import path from 'path';

let server: any;

test.beforeAll(async () => {
  server = spawn('node', ['-r', 'ts-node/register', 'src/server.ts'], {
    cwd: path.resolve(__dirname, '..'),
    stdio: 'inherit',
  });
  await new Promise((r) => setTimeout(r, 2000));
});

test.afterAll(() => {
  server.kill();
});

test('registration → view → edit → delete', async () => {
  const base = 'http://localhost:3000';
  const wallet = '0x' + Math.random().toString(16).substring(2);

  const reg = await fetch(base + '/api/auth/register', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ walletAddress: wallet, username: 'test', passwordHash: 'hash' }),
  });
  expect(reg.ok).toBeTruthy();
  const regData = await reg.json();
  const token = regData.token;

  const me = await fetch(base + '/api/users/me', {
    headers: { Authorization: `Bearer ${token}` },
  });
  expect(me.ok).toBeTruthy();
  const meData = await me.json();
  expect(meData.username).toBe('test');

  const patch = await fetch(base + '/api/users/me', {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify({ username: 'updated' }),
  });
  expect(patch.ok).toBeTruthy();
  const patchData = await patch.json();
  expect(patchData.username).toBe('updated');

  const del = await fetch(base + '/api/users/me', {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${token}` },
  });
  expect(del.status).toBe(204);
});
