import { beforeEach, describe, expect, test, vi } from "vitest";
import type { Knex } from "knex";

import { ActionProjectType, OrganizationActionScope } from "@app/db/schemas";
import { ActorType, AuthMethod } from "@app/services/auth/auth-type";

import { permissionServiceFactory } from "./permission-service";

const hooks = vi.hoisted(() => ({ memo: vi.fn(), cache: vi.fn(), ctx: new Map<string, unknown>() }));
vi.mock("@fastify/request-context", () => ({ requestContext: { get: (key: string) => hooks.ctx.get(key), set: (key: string, value: unknown) => hooks.ctx.set(key, value) } }));
vi.mock("@app/lib/request-context/request-memoizer", () => ({ requestMemoize: (...args: unknown[]) => hooks.memo(...args) }));
vi.mock("@app/lib/cache/with-cache", () => ({ withCacheFingerprint: (...args: unknown[]) => hooks.cache(...args) }));
const actor = { actor: ActorType.USER, actorId: "00000000-0000-4000-8000-000000000001", actorOrgId: "00000000-0000-4000-8000-000000000002", actorAuthMethod: AuthMethod.EMAIL };
const membership = () => ({ id: "membership", orgAuthEnforced: false, orgGoogleSsoAuthEnforced: false, bypassOrgAuthEnabled: false, rootOrgId: null, roles: [{ role: "admin", isTemporary: false }], additionalPrivileges: [], metadata: [] });
function fixture(rows = [membership()]) {
  const getPermission = vi.fn(async (_input: unknown) => rows);
  const replica = vi.fn(() => { throw new Error("REPLICA_MUST_NOT_BE_USED"); });
  const tx = Object.assign(vi.fn((table: string) => ({ where: vi.fn().mockReturnThis(), whereNull: vi.fn().mockReturnThis(), first: vi.fn(async () => table === "projects" ? {id:"project",orgId:actor.actorOrgId,type:"secret-manager",name:"project",slug:"project"} : {username:"user"}) })), { isTransaction: true });
  const deps = { permissionDAL: { getPermission, getPermissionFingerprint: replica }, projectDAL: {findById:replica}, userDAL:{findById:replica}, identityDAL:{findById:replica}, serviceTokenDAL:{findById:replica}, keyStore:{}, roleDAL:{}, additionalPrivilegeDAL:{}, groupDAL:{} };
  const service = permissionServiceFactory(deps as unknown as Parameters<typeof permissionServiceFactory>[0]);
  return { service, getPermission, replica, tx:tx as unknown as Knex.Transaction };
}
beforeEach(()=>{hooks.ctx.clear();hooks.memo.mockReset().mockImplementation((_key, read)=>read());hooks.cache.mockReset().mockImplementation(({dataFetcher})=>dataFetcher());});
describe("same-transaction permission integration",()=>{
 test("org reads bypass request memo and carry exact transaction",async()=>{const f=fixture();await f.service.getOrgPermission({...actor,orgId:actor.actorOrgId,scope:OrganizationActionScope.Any,snapshotTx:f.tx});expect(f.getPermission.mock.calls[0][0]).toMatchObject({tx:f.tx});expect(hooks.memo).not.toHaveBeenCalled();expect(hooks.cache).not.toHaveBeenCalled();});
 test("project reads bypass Redis/memo and all object lookups use tx",async()=>{const f=fixture();await f.service.getProjectPermission({...actor,projectId:"project",actionProjectType:ActionProjectType.SecretManager,snapshotTx:f.tx});expect(f.getPermission.mock.calls[0][0]).toMatchObject({tx:f.tx});expect(f.replica).not.toHaveBeenCalled();expect(hooks.memo).not.toHaveBeenCalled();expect(hooks.cache).not.toHaveBeenCalled();});
 test("missing current membership denies despite stale cache fixture",async()=>{const f=fixture([]);hooks.memo.mockResolvedValue({permission:"stale-admin"});await expect(f.service.getOrgPermission({...actor,orgId:actor.actorOrgId,scope:OrganizationActionScope.Any,snapshotTx:f.tx})).rejects.toThrow();expect(hooks.memo).not.toHaveBeenCalled();});
 test("SSO denial remains on transaction path",async()=>{const m=membership();m.orgAuthEnforced=true;m.roles=[{role:"no-access",isTemporary:false}];const f=fixture([m]);await expect(f.service.getOrgPermission({...actor,orgId:actor.actorOrgId,scope:OrganizationActionScope.Any,snapshotTx:f.tx})).rejects.toThrow();});
 test("wrong org rejected before queries",async()=>{const f=fixture();await expect(f.service.getOrgPermission({...actor,orgId:"other",scope:OrganizationActionScope.Any,snapshotTx:f.tx})).rejects.toThrow();expect(f.getPermission).not.toHaveBeenCalled();});
 test("nontransaction object rejected",async()=>{const f=fixture();await expect(f.service.getOrgPermission({...actor,orgId:actor.actorOrgId,scope:OrganizationActionScope.Any,snapshotTx:{} as Knex.Transaction})).rejects.toThrow();});
 test("ordinary org path keeps existing memo behavior",async()=>{const f=fixture();await f.service.getOrgPermission({...actor,orgId:actor.actorOrgId,scope:OrganizationActionScope.Any});expect(hooks.memo).toHaveBeenCalledOnce();});
});
