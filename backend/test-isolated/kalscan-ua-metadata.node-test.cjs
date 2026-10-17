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
  OrgPermissionIdentityActions: {Read:"read",GetToken:"get-token"}, OrgPermissionSubjects:{Identity:"identity"},
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
    if(id==="@app/ee/services/permission/permission-fns") return {validatePrivilegeChangeOperation:stockBoundary};
    if(id==="@app/ee/services/permission/org-permission" || id==="@app/ee/services/permission/project-permission") return enums;
    if(id==="@app/server/config/rateLimiter") return {readLimit:{max:1,timeWindow:1000}};
    if(id==="@app/server/plugins/auth/verify-auth") return {verifyAuth:modes=>{authModes=modes;return function verifiedHook(){}}};
    if(id.endsWith("/g2-snapshot-connection") || id==="./g2-snapshot-connection") return {withSnapshotConnection:async(db,deadline,check,work)=>{fixture.connectionCalls++;check();return work(fixture.connection,check)}};
    if(id.startsWith("@app/")) return load(path.join(root,id.slice(5)+".ts"));
    if(id.startsWith(".")) return load(path.resolve(path.dirname(file),id+".ts"));
    if(id.startsWith("node:") || ["zod","@casl/ability","@casl/ability/extra"].includes(id)) return require(id);
    throw Error("UNEXPECTED_IMPORT:"+id);
  };
  new Function("require","module","exports",js)(localRequire,m,m.exports);
  return m.exports;
}

function initializer(file,name){const text=source(file),ast=ts.createSourceFile(file,text,ts.ScriptTarget.Latest,true);let found;function visit(n){if(ts.isVariableDeclaration(n)&&ts.isIdentifier(n.name)&&n.name.text===name)found=n.initializer;ts.forEachChild(n,visit)}visit(ast);assert.ok(found,name);return found.getText(ast)}
function actualArrow(file,name,bindings){const expression=ts.transpileModule('const selected = '+initializer(file,name)+';',{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;return new Function(...Object.keys(bindings),expression+';return selected;')(...Object.values(bindings))}
const casl=require('@casl/ability');
const stockBoundary=actualArrow('ee/services/permission/permission-fns.ts','validatePrivilegeChangeOperation',{subject:casl.subject,validatePermissionBoundary:()=>{throw Error('LEGACY_NOT_QUALIFIED')}});
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


const metadata = load(path.join(root,"services/kalscan-reconciliation/kalscan-ua-metadata-contract.ts"));
const authorize = load(path.join(root,"services/kalscan-reconciliation/kalscan-ua-metadata-authorization.ts"));
const uaService = load(path.join(root,"services/kalscan-reconciliation/kalscan-ua-metadata-service.ts"));
const permsFile='ee/services/permission/permission-service.ts';
const {packRules,unpackRules}=require('@casl/ability/extra');
const isActiveRole=actualArrow(permsFile,'isActiveRole',{});
const flatten=actualArrow(permsFile,'flattenActiveRolesFromMemberships',{isActiveRole});
const hasRole=actualArrow(permsFile,'membershipsHaveActiveRole',{isActiveRole});
// Actual role builder; focused target fixtures use packed custom rules/no-access.
// Other builtin-role arrays are deliberately not runtime-qualified by this harness.
const buildRules=actualArrow(permsFile,'buildOrgPermissionRules',{OrgMembershipRole:models.OrgMembershipRole,unpackRules,orgAdminPermissions:[],orgMemberPermissions:[],orgNoAccessPermissions:[]});
class Forbidden extends Error {}
const keys=load(path.join(root,'lib/request-context/request-context-keys.ts')).RequestContextKey;
function targetMethod(f){return actualArrow(permsFile,'getFixedKalscanIdentityOrgSnapshotPermission',{
  KALSCAN:K,ForbiddenRequestError:Forbidden,TableName:T,AccessScope:models.AccessScope,ActorType:auth.ActorType,OrgMembershipRole:models.OrgMembershipRole,
  requestContext:{get:k=>context.get(k)},RequestContextKey:keys,getDelegatedOauthScopes:()=>context.get(keys.OauthScopes),
  permissionDAL:{getPermission:async args=>{f.targetPermissionCalls.push(args);assert.strictEqual(args.tx,f.tx);assert.equal(args.actorType,auth.ActorType.IDENTITY);assert.equal(args.actorId,K.identityId);assert.equal(args.scopeData.orgId,K.orgId);return f.targetMemberships}},
  createMongoAbility:casl.createMongoAbility,conditionsMatcher:casl.mongoQueryMatcher,flattenActiveRolesFromMemberships:flatten,buildOrgPermissionRules:buildRules,membershipsHaveActiveRole:hasRole
})}
const now=new Date('2026-10-17T00:00:00.000Z');
const ua=()=>({id:id(30),identityId:K.identityId,createdAt:now,updatedAt:now,accessTokenTTL:'7200',accessTokenMaxTTL:'7200',accessTokenNumUsesLimit:'0',accessTokenPeriod:'0',lockoutEnabled:true,lockoutThreshold:3,lockoutDurationSeconds:300,lockoutCounterResetSeconds:30});
const secret=(n,revoked)=>({id:id(n),identityUAId:id(30),createdAt:now,updatedAt:now,clientSecretNumUses:'0',clientSecretNumUsesLimit:'0',clientSecretTTL:'2592000',isClientSecretRevoked:revoked});
const ability=(rules)=>casl.createMongoAbility(rules);
const actorRules=()=>[{action:'read',subject:'identity'},{action:'get-token',subject:'identity'}];
function uaFixture(){const f=buildFixture();f.rows[T.IdentityGroupMembership]=[];f.rows[T.IdentityUniversalAuth]=[ua()];f.rows[T.IdentityUaClientSecret]=[secret(31,false),secret(32,true)];f.targetPermissionCalls=[];f.targetMemberships=[{id:id(7),scope:'organization',scopeOrgId:K.orgId,actorIdentityId:K.identityId,actorUserId:null,actorGroupId:null,scopeProjectId:null,scopeResourceId:null,scopeResourceType:null,isActive:true,rootOrgId:null,roles:[{role:models.OrgMembershipRole.Custom,permissions:packRules([]),isTemporary:false}],additionalPrivileges:[]}];f.actorRules=actorRules();f.permission.getOrgPermission=async args=>{assert.strictEqual(args.snapshotTx,f.tx);f.permissions.push(args);return {permission:ability(f.actorRules),hasRole:()=>true}};f.permission.getFixedKalscanIdentityOrgSnapshotPermission=targetMethod(f);return f;}
const runUa=f=>uaService.kalscanUaMetadataSnapshotService(f.db,f.permission)(f.token,'a'.repeat(64),()=>false);
test('actual fixed permission method and USER service use exact same transaction',async()=>{const f=uaFixture();const result=await runUa(f);assert.equal(f.targetPermissionCalls.length,1);assert.equal(f.permissions.length,2);assert.ok(f.permissions.every(p=>p.snapshotTx===f.tx));assert.equal(result.universalAuthMetadata.identityId,K.identityId);assert.deepEqual(result.clientSecretMetadata.map(r=>r.isClientSecretRevoked),[false,true]);for(const flag of ['executionAllowed','credentialIssuance','deliveryAllowed','inverseQualified','credentialLivenessQualified','networkBoundaryQualified'])assert.equal(result[flag],false)});
test('target permission evaluator decodes packed current target roles via actual CASL',async()=>{const f=uaFixture();f.targetMemberships[0].roles[0].permissions=packRules([{action:'manage',subject:'all'}]);const result=await f.permission.getFixedKalscanIdentityOrgSnapshotPermission({snapshotTx:f.tx,actorAuthMethod:'email'});assert.equal(result.permission.can('delete','identity'),true);assert.strictEqual(f.targetPermissionCalls[0].tx,f.tx)});
test('expired target roles are filtered by shipped active-role helper',async()=>{const f=uaFixture();f.targetMemberships[0].roles[0]={role:models.OrgMembershipRole.Custom,permissions:packRules([{action:'manage',subject:'all'}]),isTemporary:true,temporaryAccessEndTime:new Date(0)};const result=await f.permission.getFixedKalscanIdentityOrgSnapshotPermission({snapshotTx:f.tx,actorAuthMethod:'email'});assert.equal(result.permission.can('delete','identity'),false)});
test('more privileged target never substitutes for missing USER GetToken',async()=>{const f=uaFixture();f.actorRules=[{action:'read',subject:'identity'}];f.targetMemberships[0].roles[0].permissions=packRules([{action:'manage',subject:'all'}]);await refuses(runUa(f),'AUTH');assert.equal(f.targetPermissionCalls.length,1);assert.equal(f.calls.some(c=>c.table===T.IdentityUniversalAuth),false)});
for(const [name,rules] of [['explicit deny',[...actorRules(),{action:'get-token',subject:'identity',inverted:true}]],['conditional allow',[{action:'read',subject:'identity'},{action:'get-token',subject:'identity',conditions:{identityId:K.identityId}}]],['conditional deny',[...actorRules(),{action:'get-token',subject:'identity',inverted:true,conditions:{identityId:id(90)}}]],['field restriction',[{action:'read',subject:'identity'},{action:'get-token',subject:'identity',fields:['id']}]]])test('stock boundary plus unfiltered guard refuses '+name,async()=>{const f=uaFixture();f.actorRules=rules;await refuses(runUa(f),'AUTH');assert.equal(f.calls.some(c=>c.table===T.IdentityUniversalAuth),false)});
for(const [name,change] of [['group-derived',f=>f.rows[T.IdentityGroupMembership]=[{id:id(44),identityId:K.identityId}]],['missing org membership',f=>f.targetMemberships=[]],['inactive membership',f=>f.targetMemberships[0].isActive=false],['foreign membership',f=>f.targetMemberships[0].scopeOrgId=id(90)],['child org',f=>f.targetMemberships[0].rootOrgId=id(90)]])test('fixed target permission refuses '+name,async()=>{const f=uaFixture();change(f);await assert.rejects(f.permission.getFixedKalscanIdentityOrgSnapshotPermission({snapshotTx:f.tx,actorAuthMethod:'email'}),Forbidden)});
test('fixed target permission refuses nontransaction/delegated/assumed contexts',async()=>{const f=uaFixture();await assert.rejects(f.permission.getFixedKalscanIdentityOrgSnapshotPermission({snapshotTx:{},actorAuthMethod:'email'}),Forbidden);for(const [key,value] of [[keys.OauthScopes,[]],[keys.AssumedPrivilegeDetails,{}]]){context.set(key,value);await assert.rejects(f.permission.getFixedKalscanIdentityOrgSnapshotPermission({snapshotTx:f.tx,actorAuthMethod:'email'}),Forbidden);context.clear()}});
test('public org permission still refuses IDENTITY snapshotTx before querying',async()=>{const f=uaFixture();const method=actualArrow(permsFile,'getOrgPermission',{ActorType:auth.ActorType,BadRequestError:Forbidden,ForbiddenRequestError:Forbidden});await assert.rejects(method({actor:auth.ActorType.IDENTITY,actorId:K.identityId,orgId:K.orgId,actorOrgId:K.orgId,snapshotTx:f.tx}),Forbidden);assert.equal(f.targetPermissionCalls.length,0)});
test('no caller scope accepted by fixed permission seam: extra fields ignored for fixed target',async()=>{const f=uaFixture();await f.permission.getFixedKalscanIdentityOrgSnapshotPermission({snapshotTx:f.tx,actorAuthMethod:'email',actorId:id(90),orgId:id(90)});assert.equal(f.targetPermissionCalls[0].actorId,K.identityId);assert.equal(f.targetPermissionCalls[0].scopeData.orgId,K.orgId)});
test('current USER MFA retained before target/meta queries',async()=>{const f=uaFixture();f.rows[T.Users][0].isMfaEnabled=true;f.rows[T.Users][0].selectedMfaMethod='totp';f.token.isMfaVerified=true;f.token.mfaMethod='email';await refuses(runUa(f),'AUTH');assert.equal(f.targetPermissionCalls.length,0);assert.equal(f.calls.some(c=>c.table===T.IdentityUniversalAuth),false)});
for(const [name,change,code] of [['wrong UUID',f=>f.rows[T.Identity][0].id=id(90),'CONFLICT'],['missing identity',f=>f.rows[T.Identity]=[],'CONFLICT'],['duplicate identities',f=>f.rows[T.Identity].push({...f.rows[T.Identity][0],id:id(90)}),'CONFLICT'],['legacy org',f=>f.rows[T.Organization][0].shouldUseNewPrivilegeSystem=false,'SCOPE'],['missing auth',f=>f.rows[T.IdentityUniversalAuth]=[],'SCOPE'],['duplicate auth',f=>f.rows[T.IdentityUniversalAuth].push(ua()),'SCOPE'],['foreign auth identity',f=>f.rows[T.IdentityUniversalAuth][0].identityId=id(90),'SCOPE'],['33 secret metadata rows',f=>f.rows[T.IdentityUaClientSecret]=Array.from({length:33},(_,n)=>secret(n+100,false)),'CAP'],['malformed SQL counter',f=>f.rows[T.IdentityUaClientSecret][0].clientSecretNumUses='1e3','SCHEMA']])test('UA actual service refuses '+name,async()=>{const f=uaFixture();change(f);await refuses(runUa(f),code)});
test('all client rows included, no revoked filter, and SQL selects no value columns',async()=>{const f=uaFixture();f.rows[T.IdentityUniversalAuth][0].clientId='CANARY';for(const row of f.rows[T.IdentityUaClientSecret]){row.clientSecretHash='CANARY';row.clientSecretPrefix='CANARY';row.description='CANARY'}const result=await runUa(f);assert.equal(result.clientSecretMetadata.length,2);assert.equal(JSON.stringify(result).includes('CANARY'),false);const reads=f.calls.filter(c=>[T.IdentityUniversalAuth,T.IdentityUaClientSecret].includes(c.table)&&c.columns);assert.deepEqual(reads[0].columns,[...metadata.UA_METADATA_COLUMNS]);assert.deepEqual(reads[1].columns,[...metadata.CLIENT_SECRET_METADATA_COLUMNS]);for(const where of f.calls.filter(c=>c.table===T.IdentityUaClientSecret&&c.where))assert.deepEqual(Object.keys(where.where),['identityUAId'])});
for(const value of [null,undefined,true,-1,1.5,Number.MAX_SAFE_INTEGER+1,'-1','01','1.0','1e3',' 1','9007199254740992','99999999999999999999'])test('metadata integer refuses '+String(value),()=>assert.throws(()=>metadata.sqlMetadataInteger(value),/SCHEMA/));
test('canonical SQL bigints normalize safe integers only',()=>{for(const [raw,value] of [[0,0],['0',0],['7200',7200],['9007199254740991',Number.MAX_SAFE_INTEGER]])assert.equal(metadata.sqlMetadataInteger(raw),value)});
for(const [name,change,code] of [['extra clientId',r=>r.clientId='CANARY','SCHEMA'],['bad Date',r=>r.createdAt='CANARY','SCHEMA'],['invalid Date',r=>r.createdAt=new Date(NaN),'SCHEMA'],['wrong UUID',r=>r.identityId=id(99),'CONFLICT'],['string boolean',r=>r.lockoutEnabled='true','SCHEMA']])test('strict UA projection refuses '+name,()=>{const row=ua();change(row);assert.throws(()=>metadata.projectUaConfigMetadata(row),e=>e.code===code)});
test('client metadata rejects foreign UA, duplicate ID and raw prefix/hash/description',()=>{assert.throws(()=>metadata.projectClientSecretMetadata([secret(31,false),secret(31,true)],id(30)),/CONFLICT/);const row=secret(31,false);row.identityUAId=id(99);assert.throws(()=>metadata.projectClientSecretMetadata([row],id(30)),/CONFLICT/);for(const key of ['clientSecretPrefix','clientSecretHash','description'])assert.throws(()=>metadata.projectClientSecretMetadata([{...secret(31,false),[key]:'CANARY'}],id(30)),/SCHEMA/)});
test('actual new route has fixed GET/no caller scope and strict false-flag/value schema',async()=>{const f=uaFixture();let route;const router=load(path.join(root,'server/routes/v1/kalscan-ua-metadata-router.ts'));await router.registerKalscanUaMetadataRouter({route:r=>route=r},{db:f.db,permissionService:f.permission});assert.equal(route.method,'GET');assert.equal(route.url,'/organization/identities/reconciliation-snapshots/kalscan-prod-runtime/ua-metadata');assert.deepEqual(authModes,[auth.AuthMode.JWT]);assert.equal(route.schema.querystring.safeParse({identityId:id(90)}).success,false);const result=await runUa(f);assert.equal(route.schema.response[200].safeParse(result).success,true);for(const key of ['clientId','clientSecretHash','clientSecretPrefix','description'])assert.equal(route.schema.response[200].safeParse({...result,universalAuthMetadata:{...result.universalAuthMetadata,[key]:'CANARY'}}).success,false);for(const key of ['credentialLivenessQualified','networkBoundaryQualified','executionAllowed','credentialIssuance','deliveryAllowed','inverseQualified'])assert.equal(route.schema.response[200].safeParse({...result,[key]:true}).success,false)});

test('target evaluator rejects foreign principal and duplicate membership rows',async()=>{for(const change of [f=>f.targetMemberships[0].actorIdentityId=id(99),f=>f.targetMemberships.push({...f.targetMemberships[0],id:id(90)})]){const f=uaFixture();change(f);await assert.rejects(f.permission.getFixedKalscanIdentityOrgSnapshotPermission({snapshotTx:f.tx,actorAuthMethod:'email'}),Forbidden)}});
test('target additional privileges evaluated by actual active-role helper',async()=>{const f=uaFixture();f.targetMemberships[0].additionalPrivileges=[{permissions:packRules([{action:'get-token',subject:'identity'}]),isTemporary:false}];const result=await f.permission.getFixedKalscanIdentityOrgSnapshotPermission({snapshotTx:f.tx,actorAuthMethod:'email'});assert.equal(result.permission.can('get-token','identity'),true)});
test('no-access target still requires USER GetToken, not just Read/Admin badge',async()=>{const f=uaFixture();f.targetMemberships[0].roles=[{role:models.OrgMembershipRole.NoAccess,isTemporary:false}];f.actorRules=[{action:'read',subject:'identity'}];await refuses(runUa(f),'AUTH')});

test("original endpoints/shared mechanics remain byte-identical",()=>{const crypto=require("node:crypto");for(const row of [{"path":"src/server/routes/v1/g2-reconciliation-router.ts","sha256":"48a3324f35d032d348b9b9a5b48e054e260fb96174f4cd566a8d46c538859464"},{"path":"src/server/routes/v1/kalscan-reconciliation-router.ts","sha256":"dd2883ba0d990fa4931c4d40e745059ed267662a344720d4d45dcea6df39c269"},{"path":"src/services/g2-reconciliation/g2-snapshot-service.ts","sha256":"cebfd605182ff3f45bf2f6bca8dad9398ae12b923cebc3d5df04e6cd589edf35"},{"path":"src/services/g2-reconciliation/g2-snapshot-contract.ts","sha256":"7d2fb42d9c48e0c2dc6e9c11fa0424ae00f93717336c42a9ac2550da7a9a2f23"},{"path":"src/services/g2-reconciliation/g2-snapshot-connection.ts","sha256":"ee028675aa6a36f6cf95cdcfc5f66dcaf2b762310b4f38d3881d4577f30be709"},{"path":"src/services/g2-reconciliation/g2-snapshot-cancel.ts","sha256":"ab6ce02df04d8f580a89342354a60941e833ea0d839c162bb91355d1ac499528"},{"path":"src/services/g2-reconciliation/g2-snapshot-mfa.ts","sha256":"6d2b473e48ef98a8f66dda7c0593eddb8188db42b50c3e600571b3438c777017"},{"path":"src/services/kalscan-reconciliation/kalscan-snapshot-service.ts","sha256":"03cc58bc069f4249e6ced8e6feeb6a1f67bb7db48946aaf846c17e04fb6c8298"},{"path":"src/services/kalscan-reconciliation/kalscan-snapshot-contract.ts","sha256":"e3549efded5aa56092432fcfae4dfaf153e1a5cfbdd4dfe7eb0181997a8acb5c"},{"path":"src/services/kalscan-reconciliation/kalscan-snapshot-dal.ts","sha256":"50eae64194800fce6e91c15a452e04ea686b88fe17f4c26fe9aff9c00f6b0572"}])assert.equal(crypto.createHash("sha256").update(fs.readFileSync(path.resolve(root,"..",row.path))).digest("hex"),row.sha256)});

test('metadata cap accepts exactly32 rows including revoked; rejects33',()=>{const rows=Array.from({length:32},(_,n)=>secret(100+n,n%2===0));assert.equal(metadata.projectClientSecretMetadata(rows,id(30)).length,32);assert.throws(()=>metadata.projectClientSecretMetadata([...rows,secret(999,false)],id(30)),/CAP/)});
test('unknown metadata arrays/fields never become absence',()=>{assert.throws(()=>metadata.projectClientSecretMetadata(null,id(30)),/SCHEMA/);assert.throws(()=>metadata.projectUaConfigMetadata({...ua(),clientSecretTrustedIps:['CANARY']}),/SCHEMA/)});

test("public USER-only org permission implementation unchanged",()=>assert.equal(require("node:crypto").createHash("sha256").update(initializer(permsFile,"getOrgPermission")).digest("hex"),"b09a241d375e661dad74d5aa2f7fb129b16915cf309db145e7d3008decfa6d0f"));
