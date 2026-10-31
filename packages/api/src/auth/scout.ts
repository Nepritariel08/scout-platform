import type { ScoutContext, ScoutIdentity, ScoutMethods } from '@librechat/data-schemas';
import type { NextFunction, Request, Response } from 'express';

type ScoutUser = {
  id?: string;
  tenantId?: string;
  provider?: string;
  openidIssuer?: string;
  openidId?: string;
  role?: string;
};
export type ScoutRequest = Request & { user?: ScoutUser; scoutContext?: ScoutContext };
export type ScoutAdmissionDeps = ScoutMethods & {
  enforced: boolean;
  onUnavailable: () => void;
};

/** Chain only after native authentication and tenant context, never before Passport. */
export function createScoutAdmissionGate(
  deps: ScoutAdmissionDeps,
): (req: ScoutRequest, res: Response, next: NextFunction) => Promise<void> {
  return async (req, res, next): Promise<void> => {
    if (!deps.enforced) {
      next();
      return;
    }
    const user = req.user;
    if (
      user?.provider !== 'openid' ||
      !user.id ||
      !user.tenantId ||
      !user.openidIssuer ||
      !user.openidId ||
      !user.role
    ) {
      res
        .status(403)
        .json({ code: 'SCOUT_ADMISSION_DENIED', message: 'Scout access has not been granted.' });
      return;
    }
    const identity: ScoutIdentity = {
      userId: user.id,
      tenantId: user.tenantId,
      issuer: user.openidIssuer,
      subject: user.openidId,
      role: user.role,
    };
    try {
      const decision = await deps.findScoutAdmission(identity);
      if (!decision.ok) {
        res
          .status(403)
          .json({ code: 'SCOUT_ADMISSION_DENIED', message: 'Scout access has not been granted.' });
        return;
      }
      req.scoutContext = decision.context;
    } catch {
      deps.onUnavailable();
      res
        .status(503)
        .json({
          code: 'SCOUT_ADMISSION_UNAVAILABLE',
          message: 'Scout access could not be verified.',
        });
      return;
    }
    next();
  };
}
