// Actual shipped service/DAL/router functions, synthetic query/permission/transport
// seams only. No environment loader, real JWT signing, database, network, or stock e2e.
const fs = require("node:fs");
const path = require("node:path");
const assert = require("node:assert/strict");
const test = require("node:test");
const ts = require("typescript");
const root = path.resolve(__dirname,"../src");
const cache = new Map();
const context = new Map();
let fixture;
let authModes;
const enums = {
  OrgPermissionIdentityActions: {Read:"read"}, OrgPermissionSubjects:{Identity:"identity"},
  ProjectPermissionActions:{Read:"read"}, ProjectPermissionIdentityActions:{Read:"read"},
  ProjectPermissionSub:{Identity:"identity",Environments:"environments",SecretFolders:"secret-folders"}
};
const source = (f) => fs.readFileSync(path.join(root,f),"utf8");
// Import declarations are compared as complete emitted binding/specifier strings,
// sorted to ignore formatter ordering only; application tokens remain in order.
const canonical = text => {
 text=text.replace(/import\s*\{([^}]+)\}/g,(_,items)=>"import {"+items.split(",").map(v=>v.trim()).filter(Boolean).sort().join(",")+"}");
 text=ts.transpileModule(text,{compilerOptions:{module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2022}}).outputText;
 const scanner=ts.createScanner(ts.ScriptTarget.Latest,true,ts.LanguageVariant.Standard,text),tokens=[];
 for(let token=scanner.scan();token!==ts.SyntaxKind.EndOfFileToken;token=scanner.scan())tokens.push([token,scanner.getTokenText()]);
 const imports=[],body=[];
 for(let i=0;i<tokens.length;){if(tokens[i][1]==="import"){const row=[];do{row.push(tokens[i++]);}while(i<tokens.length&&row.at(-1)[1]!==";");imports.push(JSON.stringify(row));}else body.push(tokens[i++]);}
 return JSON.stringify({imports:imports.sort(),body});
};
function load(file) {
  file = path.resolve(file);
  if(cache.has(file)) return cache.get(file).exports;
  const m={exports:{}}; cache.set(file,m);
  const js=ts.transpileModule(fs.readFileSync(file,"utf8"),{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022}}).outputText;
  const localRequire=(id)=>{
    if(id==="@fastify/request-context") return {requestContext:{get:k=>context.get(k)}};
    if(id==="@app/db/schemas") return load(path.join(root,"db/schemas/models.ts"));
    if(id==="@app/ee/services/permission/org-permission" || id==="@app/ee/services/permission/project-permission") return enums;
    if(id==="@app/server/config/rateLimiter") return {readLimit:{max:1,timeWindow:1000}};
    if(id==="@app/server/plugins/auth/verify-auth") return {verifyAuth:modes=>{authModes=modes;return function verifiedHook(){}}};
    if(id.endsWith("/g2-snapshot-connection") || id==="./g2-snapshot-connection") return {withSnapshotConnection:async(db,deadline,check,work)=>{fixture.connectionCalls++;check();return work(fixture.connection,check)}};
    if(id.startsWith("@app/")) return load(path.join(root,id.slice(5)+".ts"));
    if(id.startsWith(".")) return load(path.resolve(path.dirname(file),id+".ts"));
    if(id.startsWith("node:") || ["zod","@casl/ability/extra"].includes(id)) return require(id);
    throw Error("UNEXPECTED_IMPORT:"+id);
  };
  new Function("require","module","exports",js)(localRequire,m,m.exports);
  return m.exports;
}
const c=load(path.join(root,"services/kalscan-reconciliation/kalscan-snapshot-contract.ts"));
const models=load(path.join(root,"db/schemas/models.ts"));
const {TableName:T}=models;
const auth=load(path.join(root,"services/auth/auth-type.ts"));
const K=c.KALSCAN;
const id=n=>`00000000-0000-4000-8000-${String(n).padStart(12,"0")}`;
const buildFixture = () => {
  context.clear();
  const actor=id(1),session=id(2),orgMember=id(3),projectMember=id(4),rootFolder=id(5),parent=id(6);
  const rows={
    [T.Organization]:[{id:K.orgId,rootOrgId:null,parentOrgId:null,enforceMfa:false,selectedMfaMethod:null,shouldUseNewPrivilegeSystem:true}],
    [T.Project]:[{id:K.projectId,orgId:K.orgId,slug:K.projectSlug,type:"secret-manager",deleteAfter:null}],
    [T.Environment]:[{id:K.environmentId,projectId:K.projectId,slug:"prod",deleteAfter:null}],
    [T.SecretFolder]:[{id:K.folderId,envId:K.environmentId,name:"runtime",parentId:parent},{id:parent,envId:K.environmentId,name:"scan",parentId:rootFolder},{id:rootFolder,envId:K.environmentId,name:"root",parentId:null}],
    [T.AuthTokenSession]:[{id:session,userId:actor,accessVersion:1}],
    [T.Users]:[{id:actor,isAccepted:true,isLocked:false,temporaryLockDateEnd:null,isMfaEnabled:false,selectedMfaMethod:null}],
    [T.UserGroupMembership]:[],
    [T.Identity]:[{id:K.identityId,name:K.name,orgId:K.orgId,projectId:null}],
    [T.Membership]:[{id:orgMember,actorUserId:actor,scopeOrgId:K.orgId,scope:"organization",scopeProjectId:null,status:"accepted",isActive:true},{id:projectMember,actorUserId:actor,scopeOrgId:K.orgId,scope:"project",scopeProjectId:K.projectId,status:"accepted",isActive:true},
      {id:id(7),actorIdentityId:K.identityId,actorUserId:null,actorGroupId:null,scope:"organization",scopeOrgId:K.orgId,scopeProjectId:null,scopeResourceId:null,scopeResourceType:null,isActive:true},
      {id:id(8),actorIdentityId:K.identityId,actorUserId:null,actorGroupId:null,scope:"project",scopeOrgId:K.orgId,scopeProjectId:K.projectId,scopeResourceId:null,scopeResourceType:null,isActive:true}],
    [T.MembershipRole]:[],[T.AdditionalPrivilege]:[],[T.IdentityMetadata]:[]
  };
  const calls=[];
  const tx=Object.assign(table=>{
    assert.ok(Object.hasOwn(rows,table),"No Secret/credential/unlisted table read: "+table);
    calls.push({table});
    let selected=rows[table];
    const q={
      where:filter=>{calls.push({where:filter,table});selected=selected.filter(r=>Object.entries(filter).every(([k,v])=>r[k]===v));return q},
      whereIn:(k,values)=>{selected=selected.filter(r=>values.includes(r[k]));return q},
      whereRaw:(sql,args)=>{assert.equal(sql,'lower("name" COLLATE "C") = ?');assert.deepEqual(args,[K.name]);selected=selected.filter(r=>r.name.toLowerCase()===args[0]);return q},
      select:(...columns)=>{calls.push({table,columns:columns.flat()});const keys=columns.flat();selected=selected.map(r=>Object.fromEntries(keys.map(k=>[k,r[k]])));return q},
      orderBy:()=>q,
      limit:n=>Promise.resolve(selected.slice(0,n))
    };return q;
  },{isTransaction:true,client:{query:async()=>{throw Error("Unexpected transaction query seam")}},raw:async(sql,args)=>{
    calls.push({sql,args});
    if(sql.startsWith("SELECT pg_is_in_recovery"))return {rows:[{recovery:false,isolation:"repeatable read",readOnly:"on",snapshot:"42:43:"}]};
    assert.ok(sql.startsWith("SET TRANSACTION ") || sql.startsWith("SELECT set_config("));return {rows:[]};
  }});
  const connection={};
  const db={transaction:async(work,options)=>{assert.strictEqual(options.connection,connection);return work(tx)}};
  const orgAbility={can:()=>true,rules:[{action:"read",subject:"identity"}]};
  const projectAbility={can:()=>true,rules:[{action:"read",subject:["identity","environments","secret-folders"]}]};
  const permissions=[];
  const permission={getOrgPermission:async args=>{permissions.push(args);assert.strictEqual(args.snapshotTx,tx);return {hasRole:role=>role===models.OrgMembershipRole.Admin,permission:orgAbility}},getProjectPermission:async args=>{permissions.push(args);assert.strictEqual(args.snapshotTx,tx);assert.equal(args.projectId,K.projectId);return {permission:projectAbility}}};
  const token={authTokenType:"accessToken",organizationId:K.orgId,userId:actor,tokenVersionId:session,accessVersion:1,exp:Math.floor(Date.now()/1000)+60,authMethod:"email"};
  fixture={rows,calls,tx,db,permission,token,connection,permissions,connectionCalls:0,orgAbility,projectAbility};return fixture;
};
const service=load(path.join(root,"services/kalscan-reconciliation/kalscan-snapshot-service.ts"));
const dalModule=load(path.join(root,"services/kalscan-reconciliation/kalscan-snapshot-dal.ts"));
const run=f=>service.kalscanSnapshotService(f.db,f.permission)(f.token,"a".repeat(64),()=>false);
const refuses=(promise,code)=>assert.rejects(promise,e=>e instanceof c.SnapshotRefusal && e.code===code);

test("actual service preserves roleless memberships and passes same tx to both permission reads",async()=>{const f=buildFixture();const result=await run(f);assert.equal(result.graph.identityId,K.identityId);assert.equal(result.graph.memberships.length,2);assert.ok(result.graph.memberships.every(m=>m.roles.length===0 && m.comparison==="CONFLICT"));assert.equal(f.permissions.length,2);assert.ok(f.permissions.every(p=>p.snapshotTx===f.tx));assert.equal(result.executionAllowed,false);assert.equal(result.credentialIssuance,false);assert.equal(result.deliveryAllowed,false);assert.equal(result.inverseQualified,false);assert.ok(f.calls[0].sql.startsWith("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"));});
for(const [name,mutate,code] of [
 ["wrong UUID",f=>f.rows[T.Identity][0].id=id(90),"CONFLICT"],
 ["wrong name",f=>f.rows[T.Identity][0].name="foreign","CONFLICT"],
 ["case variant",f=>f.rows[T.Identity][0].name=K.name.toUpperCase(),"CONFLICT"],
 ["missing identity",f=>f.rows[T.Identity]=[],"CONFLICT"],
 ["duplicate same name",f=>f.rows[T.Identity].push({...f.rows[T.Identity][0],id:id(90)}),"CONFLICT"],
 ["foreign identity org",f=>f.rows[T.Identity][0].orgId=id(90),"CONFLICT"],
 ["project native",f=>f.rows[T.Identity][0].projectId=K.projectId,"CONFLICT"],
 ["foreign structure project",f=>f.rows[T.Project][0].orgId=id(90),"SCOPE"],
 ["foreign env",f=>f.rows[T.Environment][0].projectId=id(90),"SCOPE"],
 ["foreign folder",f=>f.rows[T.SecretFolder][0].envId=id(90),"SCOPE"],
 ["inactive actor",f=>f.rows[T.Membership][0].isActive=false,"AUTH"],
 ["stale session",f=>f.rows[T.AuthTokenSession][0].accessVersion=2,"AUTH"],
 ["current org denies",f=>f.orgAbility.can=()=>false,"AUTH"],
 ["current project denies",f=>f.projectAbility.can=()=>false,"AUTH"],
 ["conditional read",f=>f.projectAbility.rules[0].conditions={name:"x"},"AUTH"],
 ["identity cap",f=>f.rows[T.Identity]=Array.from({length:3},(_,n)=>({...f.rows[T.Identity][0],id:id(n+90)})),"CAP"]
]) test("actual service refuses "+name,async()=>{const f=buildFixture();mutate(f);await refuses(run(f),code)});

test("actor MFA settings are read on the supplied tx: user TOTP rejects stale email",async()=>{const f=buildFixture();f.rows[T.Users][0].isMfaEnabled=true;f.rows[T.Users][0].selectedMfaMethod="totp";f.token.isMfaVerified=true;f.token.mfaMethod="email";await refuses(run(f),"AUTH");const selected=f.calls.find(c=>c.table===T.Users&&c.columns);assert.ok(selected.columns.includes("selectedMfaMethod"));});
test("current TOTP accepted, org preference precedence and email fallback retained",async()=>{let f=buildFixture();f.rows[T.Users][0].isMfaEnabled=true;f.rows[T.Users][0].selectedMfaMethod="totp";f.token.isMfaVerified=true;f.token.mfaMethod="totp";await run(f);f=buildFixture();f.rows[T.Organization][0].enforceMfa=true;f.rows[T.Organization][0].selectedMfaMethod="webauthn";f.token.isMfaVerified=true;f.token.mfaMethod="totp";await refuses(run(f),"AUTH");f=buildFixture();f.rows[T.Organization][0].enforceMfa=true;f.token.isMfaVerified=true;f.token.mfaMethod="email";await run(f);});
for(const [name,mutate] of [["org selection",f=>f.token.organizationId=id(90)],["expired",f=>f.token.exp=1],["MCP",f=>f.token.mcp=true],["OAuth",f=>f.token.oauthClientId=id(90)],["scopes",f=>f.token.scopes=["x"]]])test("token precheck "+name+" refuses before tx",async()=>{const f=buildFixture();mutate(f);await refuses(run(f),"AUTH");assert.equal(f.connectionCalls,0)});
test("assumed context refuses before tx",async()=>{const f=buildFixture();context.set("assumedPrivilegeDetails",{});await refuses(run(f),"AUTH");assert.equal(f.connectionCalls,0)});
test("DAL refuses nontransaction object",()=>assert.throws(()=>dalModule.kalscanSnapshotDAL({},async()=>{}),/TRANSACTION/));
test("management route/source contract is byte identical to frozen parent",()=>{const manifest={"parent":"3979e0dc6168e3cbdb66958f8bbade2261686cde","files":[{"path":"src/services/g2-reconciliation/g2-snapshot-mfa.ts","sha256":"6d2b473e48ef98a8f66dda7c0593eddb8188db42b50c3e600571b3438c777017"},{"path":"src/services/g2-reconciliation/g2-snapshot-dal.ts","sha256":"f1c8a8bfb12e89d92930926ecdee0c7b0f80d94733b05cbe7d4028cb14063d12"},{"path":"src/services/g2-reconciliation/g2-snapshot-contract.ts","sha256":"7d2fb42d9c48e0c2dc6e9c11fa0424ae00f93717336c42a9ac2550da7a9a2f23"},{"path":"src/services/g2-reconciliation/g2-snapshot-cancel.test.ts","sha256":"ca9a74df0601aa87a5e2b0466aa1902f8772ddbf7c648df315ef7c66dbc67cf9"},{"path":"src/services/g2-reconciliation/g2-snapshot-dal.test.ts","sha256":"22007c8b1c9dddba6c748f361c0eefeaf98cec3b76c09f0367b270f505a3efae"},{"path":"src/services/g2-reconciliation/README.md","sha256":"b85c2ad2c33eac463f65b6d1e8d6782307bf3dc34e2c833dbc4457393dc900e2"},{"path":"src/services/g2-reconciliation/g2-snapshot-connection.test.ts","sha256":"0b892e5b23109450e2527d1d85eec73525886720fbf354e11a106e67ae8a1098"},{"path":"src/services/g2-reconciliation/g2-snapshot-connection.ts","sha256":"ee028675aa6a36f6cf95cdcfc5f66dcaf2b762310b4f38d3881d4577f30be709"},{"path":"src/services/g2-reconciliation/g2-snapshot-cancel.ts","sha256":"ab6ce02df04d8f580a89342354a60941e833ea0d839c162bb91355d1ac499528"},{"path":"src/services/g2-reconciliation/g2-snapshot-service.ts","sha256":"cebfd605182ff3f45bf2f6bca8dad9398ae12b923cebc3d5df04e6cd589edf35"},{"path":"src/server/routes/v1/g2-reconciliation-router.ts","sha256":"48a3324f35d032d348b9b9a5b48e054e260fb96174f4cd566a8d46c538859464"},{"path":"src/services/auth/auth-mfa-method.ts","sha256":"3de523b7bd55b037dc2a26db07e8ca5e40382f8ad499dbb8441890f8f4a668dd"}]};const crypto=require("node:crypto");for(const row of manifest.files){assert.equal(crypto.createHash("sha256").update(fs.readFileSync(path.resolve(root,"..",row.path))).digest("hex"),row.sha256)}});

test("shipped route registers only fixed GET, JWT middleware, strict query, UUID-bound response and false gates",async()=>{buildFixture();let route;const router=load(path.join(root,"server/routes/v1/kalscan-reconciliation-router.ts"));await router.registerKalscanReconciliationRouter({route:r=>route=r},{db:fixture.db,permissionService:fixture.permission});assert.equal(route.method,"GET");assert.equal(route.url,"/organization/identities/reconciliation-snapshots/kalscan-prod-runtime");assert.deepEqual(authModes,[auth.AuthMode.JWT]);assert.equal(route.schema.querystring.safeParse({projectId:id(99)}).success,false);assert.equal(route.schema.headers.safeParse({"x-vd-reconciliation-nonce":"b".repeat(64)}).success,true);const result=await run(fixture);assert.equal(route.schema.response[200].safeParse(result).success,true);assert.equal(route.schema.response[200].safeParse({...result,scope:{...result.scope,projectId:id(99)}}).success,false);assert.equal(route.schema.response[200].safeParse({...result,graph:{...result.graph,identityId:id(99)}}).success,false);assert.equal(route.schema.response[200].safeParse({...result,secretValue:"CANARY"}).success,false);for(const key of ["executionAllowed","credentialIssuance","deliveryAllowed","inverseQualified"])assert.equal(route.schema.response[200].safeParse({...result,[key]:true}).success,false);});

test("new service orchestration is identical to retained g2 except fixed module names",()=>{
 const original=source("services/g2-reconciliation/g2-snapshot-service.ts");
 const newSource=source("services/kalscan-reconciliation/kalscan-snapshot-service.ts")
  .replaceAll("kalscanSnapshotService","g2SnapshotService").replaceAll("kalscanSnapshotDAL","g2SnapshotDAL")
  .replaceAll('"./kalscan-snapshot-contract"','"./g2-snapshot-contract"').replaceAll('"./kalscan-snapshot-dal"','"./g2-snapshot-dal"')
  .replaceAll('"../g2-reconciliation/g2-snapshot-connection"','"./g2-snapshot-connection"').replace('  KALSCAN as G2,','  G2,');
 assert.equal(canonical(newSource),canonical(original));
});
test("DAL differs only by fixed contract/module names and strict historical UUID collision check",()=>{
 const original=source("services/g2-reconciliation/g2-snapshot-dal.ts");
 const candidate=source("services/kalscan-reconciliation/kalscan-snapshot-dal.ts")
  .replaceAll("kalscanSnapshotDAL","g2SnapshotDAL").replace('  KALSCAN as G2,','  G2,')
  .replaceAll('"./kalscan-snapshot-contract"','"./g2-snapshot-contract"')
  .replaceAll('"../g2-reconciliation/g2-snapshot-mfa"','"./g2-snapshot-mfa"')
  .replace(/identities.length === 1 &&\s+identities.every\(\(i\) => i.id === G2.identityId && i.name === G2.name && i.projectId === null\)/,'identities.length <= 1 && identities.every((i) => i.name === G2.name && i.projectId === null)')
  .replace('    const id = uuid(identities[0].id);','    if (!identities.length) return { identities, memberships: [], roles: [], privileges: [], metadataIds: [] };\n    const id = uuid(identities[0].id);');
 assert.equal(canonical(candidate),canonical(original));
});
