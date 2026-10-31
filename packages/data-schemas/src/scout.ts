import { Schema } from 'mongoose';
import { createHash } from 'crypto';
import type { Model } from 'mongoose';
import { applyTenantIsolation } from './models/plugins/tenantIsolation';
import { getTenantId, SYSTEM_TENANT_ID } from './config/tenantContext';

export type ScoutIdentity = {
  userId: string;
  tenantId: string;
  issuer: string;
  subject: string;
  role: string;
};

export type ScoutRequester = {
  database: string;
  uid: number;
  companyIds: number[];
  credentialRef: string;
};

export type ScoutContext = Readonly<{
  userId: string;
  tenantId: string;
  actor: 'owner' | 'employee' | 'customer';
  policyRevision: string;
  bindingRevision: string;
  tools: readonly string[];
  requester: Readonly<Omit<ScoutRequester, 'companyIds'> & { companyIds: readonly number[] }>;
}>;

export type ScoutDecision = { ok: true; context: ScoutContext } | { ok: false };
export type ScoutPermissions = Record<string, Record<string, boolean>>;
export type ScoutPolicy = {
  tenantId: string;
  revision: string;
  active: boolean;
  validUntil: Date;
  role: string;
  permissionsDigest: string;
};
export type ScoutMembership = ScoutIdentity & {
  active: boolean;
  validUntil: Date;
  revision: string;
  policyRevision: string;
  actor: ScoutContext['actor'];
  tools: string[];
  requester: ScoutRequester;
};
export type ScoutModels = {
  ScoutPolicy: Model<ScoutPolicy>;
  ScoutMembership: Model<ScoutMembership>;
};
export type ScoutMethods = {
  findScoutAdmission: (identity: ScoutIdentity, now?: Date) => Promise<ScoutDecision>;
};

const identifier = { type: String, required: true, minlength: 1, maxlength: 255 };
const positiveInteger = { type: Number, required: true, min: 1, validate: Number.isSafeInteger };

/** Hash the complete approved role map, including false flags and newly added capabilities. */
export function digestScoutPermissions(permissions: ScoutPermissions): string {
  const sorted = Object.fromEntries(
    Object.keys(permissions)
      .sort()
      .map((block) => [
        block,
        Object.fromEntries(
          Object.keys(permissions[block])
            .sort()
            .map((permission) => [permission, permissions[block][permission]]),
        ),
      ]),
  );
  return createHash('sha256').update(JSON.stringify(sorted)).digest('hex');
}

export function createScoutModels(mongoose: typeof import('mongoose')): ScoutModels {
  const policySchema = new Schema<ScoutPolicy>(
    {
      tenantId: identifier,
      revision: identifier,
      active: { type: Boolean, required: true, default: false },
      validUntil: { type: Date, required: true },
      role: identifier,
      permissionsDigest: { type: String, required: true, match: /^[a-f0-9]{64}$/ },
    },
    { strict: 'throw', timestamps: true },
  );
  policySchema.index({ tenantId: 1 }, { unique: true });
  applyTenantIsolation(policySchema);

  const requesterSchema = new Schema<ScoutRequester>(
    {
      database: identifier,
      uid: positiveInteger,
      companyIds: {
        type: [Number],
        required: true,
        validate: (values: number[]) =>
          values.length > 0 &&
          new Set(values).size === values.length &&
          values.every((v) => Number.isSafeInteger(v) && v > 0),
      },
      credentialRef: { ...identifier, match: /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$/ },
    },
    { _id: false, strict: 'throw' },
  );
  const membershipSchema = new Schema<ScoutMembership>(
    {
      tenantId: identifier,
      userId: { ...identifier, match: /^[a-f0-9]{24}$/ },
      issuer: identifier,
      subject: identifier,
      role: identifier,
      revision: identifier,
      policyRevision: identifier,
      active: { type: Boolean, required: true, default: false },
      validUntil: { type: Date, required: true },
      actor: { type: String, required: true, enum: ['owner', 'employee', 'customer'] },
      tools: { type: [String], default: [] },
      requester: { type: requesterSchema, required: true },
    },
    { strict: 'throw', timestamps: true },
  );
  membershipSchema.index({ tenantId: 1, userId: 1 }, { unique: true });
  membershipSchema.index({ tenantId: 1, issuer: 1, subject: 1 }, { unique: true });
  applyTenantIsolation(membershipSchema);
  return {
    ScoutPolicy:
      mongoose.models.ScoutPolicy || mongoose.model<ScoutPolicy>('ScoutPolicy', policySchema),
    ScoutMembership:
      mongoose.models.ScoutMembership ||
      mongoose.model<ScoutMembership>('ScoutMembership', membershipSchema),
  };
}

type Lookup = ScoutMembership & {
  policies: ScoutPolicy[];
  roles: Array<{ permissions: ScoutPermissions }>;
};

/** One scoped DB query; no membership/role cache may turn revocation into an allow. */
export function createScoutMethods(mongoose: typeof import('mongoose')): ScoutMethods {
  const models = createScoutModels(mongoose);
  return {
    async findScoutAdmission(identity, now = new Date()): Promise<ScoutDecision> {
      const tenant = getTenantId();
      if (!tenant || tenant === SYSTEM_TENANT_ID || tenant !== identity.tenantId)
        return { ok: false };
      if (!identity.userId || !identity.issuer || !identity.subject || !identity.role)
        return { ok: false };
      const [row] = await models.ScoutMembership.aggregate<Lookup>([
        { $match: { ...identity, active: true, validUntil: { $gt: now } } },
        {
          $lookup: {
            from: models.ScoutPolicy.collection.name,
            let: { tenant: '$tenantId' },
            pipeline: [{ $match: { $expr: { $eq: ['$tenantId', '$$tenant'] } } }],
            as: 'policies',
          },
        },
        {
          $lookup: {
            from: mongoose.models.Role.collection.name,
            let: { tenant: '$tenantId', role: '$role' },
            pipeline: [
              {
                $match: {
                  $expr: {
                    $and: [{ $eq: ['$tenantId', '$$tenant'] }, { $eq: ['$name', '$$role'] }],
                  },
                },
              },
              { $project: { permissions: 1 } },
            ],
            as: 'roles',
          },
        },
      ]).exec();
      const policy = row?.policies[0];
      const role = row?.roles[0];
      if (
        !row ||
        row.policies.length !== 1 ||
        row.roles.length !== 1 ||
        !policy?.active ||
        !(policy.validUntil > now) ||
        policy.role !== identity.role ||
        policy.revision !== row.policyRevision ||
        !role?.permissions ||
        digestScoutPermissions(role.permissions) !== policy.permissionsDigest
      ) {
        return { ok: false };
      }
      return {
        ok: true,
        context: Object.freeze({
          userId: identity.userId,
          tenantId: tenant,
          actor: row.actor,
          policyRevision: policy.revision,
          bindingRevision: row.revision,
          tools: Object.freeze([...row.tools]),
          requester: Object.freeze({
            ...row.requester,
            companyIds: Object.freeze([...row.requester.companyIds]),
          }),
        }),
      };
    },
  };
}
