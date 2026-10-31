import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import type { ScoutIdentity, ScoutMembership, ScoutPolicy } from './scout';
import { createScoutMethods, createScoutModels, digestScoutPermissions } from './scout';
import { runAsSystem, tenantStorage } from './config/tenantContext';
import { createModels } from './models';

let mongo: MongoMemoryServer;
const identity: ScoutIdentity = {
  userId: '012345678901234567890123',
  tenantId: 'customer-a',
  issuer: 'https://idp.qualification.invalid',
  subject: 'subject-a',
  role: 'USER',
};
const permissions = { MCP_SERVERS: { USE: false, CREATE: false } };
let models: ReturnType<typeof createModels>;
let methods: ReturnType<typeof createScoutMethods>;
const scoped = <T>(fn: () => Promise<T>): Promise<T> =>
  tenantStorage.run({ tenantId: identity.tenantId }, fn);
const find = (input = identity) => scoped(async () => methods.findScoutAdmission(input));

beforeAll(async () => {
  mongo = await MongoMemoryServer.create();
  await mongoose.connect(mongo.getUri());
  models = createModels(mongoose);
  methods = createScoutMethods(mongoose);
  await Promise.all([models.ScoutPolicy.init(), models.ScoutMembership.init(), models.Role.init()]);
});
afterAll(async () => {
  await mongoose.disconnect();
  await mongo.stop();
});
beforeEach(async () => {
  await runAsSystem(async () => {
    await Promise.all([
      models.ScoutPolicy.deleteMany({}),
      models.ScoutMembership.deleteMany({}),
      models.Role.deleteMany({}),
    ]);
    await models.Role.create({ name: 'USER', tenantId: identity.tenantId, permissions });
    const policy: ScoutPolicy = {
      tenantId: identity.tenantId,
      revision: 'policy-1',
      active: true,
      validUntil: new Date(Date.now() + 60000),
      role: 'USER',
      permissionsDigest: digestScoutPermissions(permissions),
    };
    const member: ScoutMembership = {
      ...identity,
      active: true,
      revision: 'binding-1',
      policyRevision: 'policy-1',
      validUntil: new Date(Date.now() + 60000),
      actor: 'customer',
      tools: ['queue.draft'],
      requester: {
        database: 'qualification',
        uid: 15,
        companyIds: [1],
        credentialRef: 'customer-a-requester',
      },
    };
    await models.ScoutPolicy.create(policy);
    await models.ScoutMembership.create(member);
  });
});

it('returns the exact server binding and a frozen context', async () => {
  const result = await find();
  expect(result.ok).toBe(true);
  if (!result.ok) throw new Error('Admission refused');
  expect(result.context.requester).toEqual({
    database: 'qualification',
    uid: 15,
    companyIds: [1],
    credentialRef: 'customer-a-requester',
  });
  expect(result.context.policyRevision).toBe('policy-1');
  expect(Object.isFrozen(result.context.requester.companyIds)).toBe(true);
});
it.each(['userId', 'tenantId', 'issuer', 'subject', 'role'] as const)(
  'refuses a different %s',
  async (field) => {
    expect(await find({ ...identity, [field]: 'different' })).toEqual({ ok: false });
  },
);
it('refuses absent and system tenant contexts', async () => {
  expect(await methods.findScoutAdmission(identity)).toEqual({ ok: false });
  expect(await runAsSystem(async () => methods.findScoutAdmission(identity))).toEqual({
    ok: false,
  });
});
it.each(['active', 'validUntil', 'policyRevision'] as const)(
  'honors membership %s changes without a cache',
  async (field) => {
    expect((await find()).ok).toBe(true);
    await scoped(async () => {
      await models.ScoutMembership.updateOne(
        { userId: identity.userId },
        {
          $set: {
            [field]:
              field === 'active' ? false : field === 'validUntil' ? new Date(0) : 'old-policy',
          },
        },
      );
    });
    expect(await find()).toEqual({ ok: false });
  },
);
it.each(['active', 'validUntil', 'revision', 'role'] as const)(
  'honors tenant-policy %s changes',
  async (field) => {
    await scoped(async () => {
      await models.ScoutPolicy.updateOne(
        {},
        {
          $set: {
            [field]: field === 'active' ? false : field === 'validUntil' ? new Date(0) : 'changed',
          },
        },
      );
    });
    expect(await find()).toEqual({ ok: false });
  },
);
it('refuses a missing tenant policy or role rather than creating defaults', async () => {
  await scoped(async () => {
    await models.ScoutPolicy.deleteMany({});
  });
  expect(await find()).toEqual({ ok: false });
  await runAsSystem(async () => {
    await models.Role.deleteMany({});
  });
  expect(await find()).toEqual({ ok: false });
  expect(await scoped(async () => models.Role.countDocuments({}))).toBe(0);
});
it('refuses drift in the real tenant role, even if membership remains active', async () => {
  expect((await find()).ok).toBe(true);
  await scoped(async () => {
    await models.Role.updateOne(
      { name: 'USER' },
      { $set: { 'permissions.MCP_SERVERS.USE': true } },
    );
  });
  expect(await find()).toEqual({ ok: false });
});
it('does not use a platform role as the tenant role', async () => {
  await runAsSystem(async () => {
    await models.Role.deleteMany({});
    await models.Role.create({ name: 'USER', permissions });
  });
  expect(await find()).toEqual({ ok: false });
});
it('rejects duplicate issuer/subject enrollment within a tenant', async () => {
  await scoped(async () => {
    const row = await models.ScoutMembership.findOne().lean();
    await expect(
      models.ScoutMembership.create({ ...row, _id: undefined, userId: '112345678901234567890123' }),
    ).rejects.toMatchObject({ code: 11000 });
  });
});
it('validates requester identity fields and refuses secret material', async () => {
  await scoped(async () => {
    const row = await models.ScoutMembership.findOne().lean();
    const request = {
      database: 'qualification',
      uid: 0,
      companyIds: [1, 1],
      credentialRef: '../../secret',
    };
    await expect(
      new models.ScoutMembership({ ...row, requester: request }).validate(),
    ).rejects.toThrow();
    await expect(
      new models.ScoutMembership({
        ...row,
        requester: { ...row?.requester, apiKey: 'never-store-keys' },
      }).validate(),
    ).rejects.toThrow(/apiKey/);
  });
});
it('hashes permissions consistently while detecting a newly added capability', () => {
  expect(digestScoutPermissions({ B: { b: false, a: true }, A: { x: false } })).toBe(
    digestScoutPermissions({ A: { x: false }, B: { a: true, b: false } }),
  );
  expect(digestScoutPermissions(permissions)).not.toBe(
    digestScoutPermissions({ ...permissions, NEW_TOOL: { USE: true } }),
  );
});
