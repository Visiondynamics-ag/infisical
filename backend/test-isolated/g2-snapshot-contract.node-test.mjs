// Runs the actual shipped dependency-free contract. No environment loading, DB,
// Redis, credentials, network, packages, or stock Vitest/e2e bootstrap.
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import assert from 'node:assert/strict';
import test from 'node:test';
const source = readFileSync(new URL('../src/services/g2-reconciliation/g2-snapshot-contract.ts', import.meta.url), 'utf8');
const c = await import(`data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source)).toString('base64')}`);
const { G2, projectGraph, checkTransaction, exactLeafRule, serializeSnapshot } = c;
const id = (n) => `00000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const rule = () => ({ action: ['describeSecret','readValue'], subject: 'secrets', conditions: {environment: {$eq:'prod'},secretPath:{$glob:G2.folderPath}} });
const graph = () => ({
 identities: [{id:id(1),name:G2.name,orgId:G2.orgId,projectId:null}],
 memberships: [{id:id(2),actorIdentityId:id(1),actorUserId:null,actorGroupId:null,scope:'project',scopeOrgId:G2.orgId,scopeProjectId:G2.projectId,scopeResourceId:null,scopeResourceType:null,isActive:true}],
 roles: [{id:id(3),membershipId:id(2),role:'no-access',customRoleId:null,isTemporary:false}],
 privileges: [{id:id(4),actorIdentityId:id(1),actorUserId:null,orgId:null,projectId:G2.projectId,name:G2.grantName,isTemporary:false,rules:[rule()]}], metadataIds: []
});
const refuses = (fn, code) => assert.throws(fn, e => e instanceof c.SnapshotRefusal && e.message === code);
test('expected graph preserves every observed UUID and exact comparison',()=>{const p=projectGraph(graph());assert.equal(p.identityId,id(1));assert.equal(p.memberships[0].id,id(2));assert.equal(p.memberships[0].roles[0].id,id(3));assert.equal(p.privileges[0].id,id(4));assert.equal(p.privileges[0].comparison,'EXACT_RULE')});
test('roleless membership retained as conflict',()=>{const g=graph();g.roles=[];const p=projectGraph(g);assert.equal(p.memberships.length,1);assert.deepEqual(p.memberships[0].roles,[]);assert.equal(p.memberships[0].comparison,'CONFLICT')});
test('orphan privilege retained independently',()=>{const g=graph();g.memberships=[];g.roles=[];const p=projectGraph(g);assert.equal(p.privileges.length,1);assert.equal(p.privileges[0].membershipPresent,false);assert.equal(p.privileges[0].comparison,'CONFLICT')});
test('membership with no privileges retained',()=>{const g=graph();g.privileges=[];assert.equal(projectGraph(g).memberships.length,1)});
test('only snapshot absence, no action permission inferred',()=>{const p=projectGraph({identities:[],memberships:[],roles:[],privileges:[],metadataIds:[]});assert.equal(p.identityState,'ABSENT_AT_SNAPSHOT');assert.equal(p.identityId,null);assert.equal('executionAllowed' in p,false)});
test('absence with supplied rows is invalid',()=>{const g=graph();g.identities=[];refuses(()=>projectGraph(g),'SCHEMA')});
test('same-name UUID collision refuses',()=>{const g=graph();g.identities.push({...g.identities[0],id:id(9)});refuses(()=>projectGraph(g),'CONFLICT')});
test('case variant refuses',()=>{const g=graph();g.identities[0].name=G2.name.toUpperCase();refuses(()=>projectGraph(g),'CONFLICT')});
test('project-native identity refuses',()=>{const g=graph();g.identities[0].projectId=G2.projectId;refuses(()=>projectGraph(g),'CONFLICT')});
test('duplicate UUID refuses',()=>{const g=graph();g.roles.push({...g.roles[0]});refuses(()=>projectGraph(g),'SCHEMA')});
test('duplicate destination membership refuses',()=>{const g=graph();g.memberships.push({...g.memberships[0],id:id(8)});refuses(()=>projectGraph(g),'CONFLICT')});
test('out-of-scope membership never disclosed',()=>{const g=graph();g.memberships[0].scopeProjectId=id(99);refuses(()=>projectGraph(g),'SCOPE')});
test('out-of-scope orphan privilege refuses',()=>{const g=graph();g.privileges[0].projectId=id(99);refuses(()=>projectGraph(g),'SCOPE')});
test('resource membership refuses',()=>{const g=graph();g.memberships[0].scopeResourceId=id(99);refuses(()=>projectGraph(g),'SCOPE')});
test('wrong membership actor refuses',()=>{const g=graph();g.memberships[0].actorIdentityId=id(99);refuses(()=>projectGraph(g),'SCHEMA')});
test('wrong privilege actor refuses',()=>{const g=graph();g.privileges[0].actorUserId=id(99);refuses(()=>projectGraph(g),'SCHEMA')});
test('role pointing outside selected memberships refuses',()=>{const g=graph();g.roles[0].membershipId=id(99);refuses(()=>projectGraph(g),'SCHEMA')});
for(const field of ['role','customRoleId','isTemporary']) test(`non-exact role ${field} stays conflict`,()=>{const g=graph();g.roles[0][field]=field==='isTemporary'?true:field==='role'?'admin':id(99);assert.equal(projectGraph(g).memberships[0].comparison,'CONFLICT')});
test('inactive membership stays conflict',()=>{const g=graph();g.memberships[0].isActive=false;assert.equal(projectGraph(g).memberships[0].comparison,'CONFLICT')});
test('temporary grant stays conflict',()=>{const g=graph();g.privileges[0].isTemporary=true;assert.equal(projectGraph(g).privileges[0].comparison,'CONFLICT')});
for(const [kind,max] of Object.entries(c.LIMITS)) test(`${kind} cap cannot become completeness`,()=>{const g=graph();const key=kind==='metadata'?'metadataIds':kind;g[key]=Array.from({length:max+1},(_,i)=>({id:id(i+100)}));refuses(()=>projectGraph(g),'CAP')});
for(const [field,value] of [['recovery',true],['isolation','read committed'],['readOnly','off'],['snapshot','canary']]) test(`transaction ${field} mismatch refuses`,()=>{const row={recovery:false,isolation:'repeatable read',readOnly:'on',snapshot:'42:43:'};row[field]=value;refuses(()=>checkTransaction(row),'TRANSACTION')});
test('expected transaction properties accepted',()=>checkTransaction({recovery:false,isolation:'repeatable read',readOnly:'on',snapshot:'42:50:43,46'}));
test('CASL explicit inverted=false remains exact',()=>assert.equal(exactLeafRule([{...rule(),inverted:false}]),true));
for(const mutate of [r=>r.action.push('create'),r=>r.conditions.secretPath.$glob+='/*',r=>r.inverted=true,r=>r.fields=['secretValue'],r=>r.reason='canary',r=>r.subject=['secrets','identity'],r=>r.conditions.environment.$eq='protonet']) test(`non-exact grant ${mutate.toString()} is held`,()=>{const r=rule();mutate(r);assert.equal(exactLeafRule([r]),false)});
test('canary rule and arbitrary names/metadata never serialized',()=>{const g=graph();g.privileges[0].name='CANARY';g.privileges[0].rules=[{canary:'CANARY'}];g.identities[0].canary='CANARY';const s=serializeSnapshot(projectGraph(g));assert.equal(s.includes('CANARY'),false)});
test('response byte cap enforced',()=>refuses(()=>serializeSnapshot('x'.repeat(65537)),'CAP'));
