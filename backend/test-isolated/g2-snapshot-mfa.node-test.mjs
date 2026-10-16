import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import assert from 'node:assert/strict';
import test from 'node:test';
// Load the actual shipped pure helper/validator. Only static module specifiers are
// mapped to data URLs; function bodies are not extracted, mocked or reimplemented.
const source = (file) => stripTypeScriptTypes(readFileSync(new URL(`../src/${file}`,import.meta.url),'utf8'),{mode:'transform'});
const url = (text) => `data:text/javascript;base64,${Buffer.from(text).toString('base64')}`;
const types = url(source('services/auth/auth-type.ts'));
const contract = url(source('services/g2-reconciliation/g2-snapshot-contract.ts'));
const helper = url(source('services/auth/auth-mfa-method.ts').replace('"./auth-type"',JSON.stringify(types)));
const validator = await import(url(source('services/g2-reconciliation/g2-snapshot-mfa.ts')
 .replace('"../auth/auth-mfa-method"',JSON.stringify(helper)).replace('"./g2-snapshot-contract"',JSON.stringify(contract))));
const check=validator.requireSnapshotMfa;
const deny = (...args) => assert.throws(()=>check(...args), e=>e.message==='AUTH');
test('user TOTP requires verified TOTP, rejects verified email',()=>{check({enforceMfa:false},{isMfaEnabled:true,selectedMfaMethod:'totp'},true,'totp');deny({enforceMfa:false},{isMfaEnabled:true,selectedMfaMethod:'totp'},true,'email')});
test('organization method takes precedence',()=>{const o={enforceMfa:true,selectedMfaMethod:'webauthn'},u={isMfaEnabled:true,selectedMfaMethod:'totp'};check(o,u,true,'webauthn');deny(o,u,true,'totp')});
test('organization null method defaults to email',()=>{const o={enforceMfa:true,selectedMfaMethod:null};check(o,{},true,'email');deny(o,{},true,'totp');deny(o,{},true,undefined)});
test('user null method defaults to email',()=>{const u={isMfaEnabled:true,selectedMfaMethod:null};check({enforceMfa:false},u,true,'email');deny({enforceMfa:false},u,true,'totp')});
test('stored non-enforced org method does not override user',()=>check({enforceMfa:false,selectedMfaMethod:'email'},{isMfaEnabled:true,selectedMfaMethod:'totp'},true,'totp'));
test('unverified required method denied',()=>deny({enforceMfa:true},{},false,'email'));
test('missing token method denied when user enabled',()=>deny({},{isMfaEnabled:true,selectedMfaMethod:'totp'},true,undefined));
test('no MFA state accepts ordinary session without method',()=>check({enforceMfa:false},{isMfaEnabled:false},false,undefined));
test('unknown currently required method fails closed for ordinary methods',()=>deny({enforceMfa:true,selectedMfaMethod:'unknown'},{},true,'email'));
test('unknown method remains denied even if token matches',()=>deny({enforceMfa:true,selectedMfaMethod:'unknown'},{},true,'unknown'));
