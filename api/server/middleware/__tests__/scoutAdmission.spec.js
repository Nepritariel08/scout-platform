const { MongoMemoryServer } = require('mongodb-memory-server');

const savedEnv = { ...process.env };
let mongo;
let mongoose;
let schemas;
let request;
let jwt;
let app;
let users;
let tokens;
let reached;
let models;
const issuer = 'https://identity.qualification.invalid';
const permissions = { MCP_SERVERS: { USE: false, CREATE: false } };

beforeAll(async () => {
  process.env.SCOUT_ADMISSION_ENFORCED = 'true';
  process.env.TENANT_ISOLATION_STRICT = 'true';
  process.env.BAN_VIOLATIONS = 'false';
  process.env.JWT_SECRET = 'synthetic-scout-jwt-fixture-only';
  process.env.AUTH_USER_CACHE_MODE = 'off';
  jest.resetModules();
  const express = require('express');
  const passport = require('passport');
  mongoose = require('mongoose');
  schemas = require('@librechat/data-schemas');
  request = require('supertest');
  jwt = require('jsonwebtoken');
  mongo = await MongoMemoryServer.create();
  await mongoose.connect(mongo.getUri());
  models = schemas.createModels(mongoose);
  await Promise.all(Object.values(models).map((model) => model.init()));
  passport.use('jwt', require('~/strategies/jwtStrategy')());
  const requireJwtAuth = require('../requireJwtAuth');
  app = express();
  app.use(express.json());
  app.use(passport.initialize());
  reached = jest.fn((req, res) =>
    res.json({
      tenantId: req.scoutContext.tenantId,
      requesterUid: req.scoutContext.requester.uid,
      policyRevision: req.scoutContext.policyRevision,
    }),
  );
  app.post('/private', requireJwtAuth, reached);
  const failedGate = require('@librechat/api').createScoutAdmissionGate({
    enforced: true,
    findScoutAdmission: async () => {
      throw new Error('private-credential-and-query-details');
    },
    onUnavailable: () => {},
  });
  app.post('/authority-unavailable', requireJwtAuth, failedGate, reached);
}, 180000);

afterAll(async () => {
  await mongoose.disconnect();
  await mongo?.stop();
  process.env = savedEnv;
});
beforeEach(async () => {
  reached.mockClear();
  users = [];
  tokens = [];
  await schemas.runAsSystem(async () => {
    await Promise.all([
      models.User.deleteMany({}),
      models.Role.deleteMany({}),
      models.ScoutMembership.deleteMany({}),
      models.ScoutPolicy.deleteMany({}),
    ]);
    for (const [index, tenantId] of ['customer-a', 'customer-b'].entries()) {
      const role = await models.Role.create({ tenantId, name: 'USER', permissions });
      const user = await models.User.create({
        tenantId,
        provider: 'openid',
        role: 'USER',
        email: 'same-address@qualification.invalid',
        emailVerified: true,
        openidIssuer: issuer,
        openidId: `subject-${index}`,
        name: tenantId,
      });
      await models.ScoutPolicy.create({
        tenantId,
        revision: 'policy-1',
        active: true,
        role: 'USER',
        validUntil: new Date(Date.now() + 600000),
        permissionsDigest: schemas.digestScoutPermissions(role.toObject().permissions),
      });
      await models.ScoutMembership.create({
        tenantId,
        userId: user.id,
        issuer,
        subject: user.openidId,
        role: 'USER',
        active: true,
        actor: 'customer',
        revision: 'binding-1',
        policyRevision: 'policy-1',
        validUntil: new Date(Date.now() + 600000),
        tools: ['queue.draft'],
        requester: {
          database: 'qualification',
          uid: 15 + index,
          companyIds: [1],
          credentialRef: `requester-${index}`,
        },
      });
      users.push(user);
      tokens.push(jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '5m' }));
    }
  });
});

const send = (token = tokens[0], body = {}) =>
  request(app).post('/private').set('Authorization', `Bearer ${token}`).send(body);

it('uses native JWT authentication and the exact configured requester', async () => {
  const response = await send();
  expect(response.status).toBe(200);
  expect(response.body).toEqual({
    tenantId: 'customer-a',
    requesterUid: 15,
    policyRevision: 'policy-1',
  });
  expect(reached).toHaveBeenCalledTimes(1);
});
it('ignores caller tenant, role, requester and context fields', async () => {
  const response = await request(app)
    .post('/private')
    .set('Authorization', `Bearer ${tokens[0]}`)
    .set('X-Tenant-Id', 'customer-b')
    .set('X-Odoo-Uid', '999')
    .send({
      tenantId: 'customer-b',
      role: 'ADMIN',
      requesterUid: 999,
      scoutContext: { requester: { uid: 999 } },
    });
  expect(response.status).toBe(200);
  expect(response.body.requesterUid).toBe(15);
  expect(response.body.tenantId).toBe('customer-a');
  expect((await send(tokens[1])).body.requesterUid).toBe(16);
});
it('denies a retired membership on the next request with the same still-valid bearer', async () => {
  expect((await send()).status).toBe(200);
  await schemas.runAsSystem(async () => {
    await models.ScoutMembership.updateOne({ userId: users[0].id }, { active: false });
  });
  expect((await send()).status).toBe(403);
  expect(reached).toHaveBeenCalledTimes(1);
});
it.each(['policy', 'role', 'identity', 'membership'])(
  'denies %s drift before the private handler',
  async (kind) => {
    await schemas.runAsSystem(async () => {
      if (kind === 'policy')
        await models.ScoutPolicy.updateOne({ tenantId: 'customer-a' }, { revision: 'policy-2' });
      if (kind === 'role')
        await models.Role.updateOne(
          { tenantId: 'customer-a' },
          { 'permissions.MCP_SERVERS.USE': true },
        );
      if (kind === 'identity')
        await models.User.updateOne(
          { _id: users[0]._id },
          { openidIssuer: 'https://other.qualification.invalid' },
        );
      if (kind === 'membership') await models.ScoutMembership.deleteOne({ userId: users[0].id });
    });
    expect((await send()).status).toBe(403);
    expect(reached).not.toHaveBeenCalled();
  },
);
it('denies a local account even when its metadata resembles the bound identity', async () => {
  await schemas.runAsSystem(async () => {
    await models.User.updateOne({ _id: users[0]._id }, { provider: 'local' });
  });
  expect((await send()).status).toBe(403);
  expect(reached).not.toHaveBeenCalled();
});
it('rejects an invalid or expired bearer through the native strategy', async () => {
  expect((await send(tokens[0] + 'tampered')).status).toBe(401);
  const expired = jwt.sign({ id: users[0].id }, process.env.JWT_SECRET, { expiresIn: -1 });
  expect((await send(expired)).status).toBe(401);
  expect(reached).not.toHaveBeenCalled();
});
it('fails closed without exposing an authority failure', async () => {
  const response = await request(app)
    .post('/authority-unavailable')
    .set('Authorization', `Bearer ${tokens[0]}`)
    .send({});
  expect(response.status).toBe(503);
  expect(response.body).toEqual({
    code: 'SCOUT_ADMISSION_UNAVAILABLE',
    message: 'Scout access could not be verified.',
  });
  expect(JSON.stringify(response.body)).not.toContain('private-credential');
  expect(reached).not.toHaveBeenCalled();
});
