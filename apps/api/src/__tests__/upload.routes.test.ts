jest.mock('@pinata/sdk', () => {
    return function MockPinata() {
        return {
            pinFileToIPFS: async () => ({
                IpfsHash: 'bafybeigdyrandomcidfor-tests',
                PinSize: 4,
                Timestamp: new Date().toISOString(),
            }),
        };
    };
});

import request from 'supertest';
import app from '../app';
import { resetDb } from '../testUtils';

beforeAll(() => {
    process.env.PINATA_JWT = process.env.PINATA_JWT || 'dummy';
});

beforeEach(async () => {
    await resetDb();
});

async function login() {
    const email = 'up@test.io', password = 'CorrectHorse1!';
    await request(app).post('/auth/register').send({ email, password });
    const r = await request(app).post('/auth/login').send({ email, password });
    return r.body.token as string;
}

it('rejects without token', async () => {
    const r = await request(app).post('/api/upload');
    expect(r.status).toBe(401);
});

it('accepts multipart upload and returns CID', async () => {
    const token = await login();

    const buf = Buffer.from('test');
    const r = await request(app)
        .post('/api/upload')
        .set('Authorization', `Bearer ${token}`)
        .attach('file', buf, { filename: 'tiny.txt', contentType: 'text/plain' });

    expect(r.status).toBe(200);
    expect(r.body.ok).toBe(true);
    expect(r.body.cid).toMatch(/^bafy/);
    expect(r.body.provider).toBe('pinata');
});