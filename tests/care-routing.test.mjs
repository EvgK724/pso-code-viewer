import test from 'node:test';
import assert from 'node:assert/strict';
import {ROLES,GROUPS,roleGroup,canSendGroup,participatesInGroup,isReplyKind,isGroupConversationKind} from '../docs/care-routing.mjs';

test('group conversations include PSO and only their own specialists, never the bot',()=>{
  for(const role of ROLES)for(const group of GROUPS){
    const allowed=['admin','neurologist'].includes(role)||roleGroup(role)===group;
    assert.equal(participatesInGroup(role,group),allowed,role+' in '+group);
    assert.equal(canSendGroup(role,group,'group_reply'),allowed,role+' replying to '+group);
    assert.equal(canSendGroup(role,group,'discussion'),allowed&&group==='rehab1',role+' starting in '+group);
  }
  assert.equal(participatesInGroup('bot','rehab1'),false);
  assert.equal(participatesInGroup('unknown','orit'),false);
  assert.equal(canSendGroup('admin','unknown','group_reply'),false);
});

test('legacy private replies and admission permissions remain separate from new conversations',()=>{
  assert.equal(canSendGroup('bot','orit','admission'),true);
  assert.equal(canSendGroup('bot','rehab1','admission'),false);
  assert.equal(canSendGroup('neurologist','orit','admission'),false);
  assert.equal(canSendGroup('psychologist','rehab1','reply'),false);
  assert.equal(canSendGroup('psychologist','rehab1','review'),false);
  assert.equal(canSendGroup('intensivist','orit','reply'),true);
  assert.equal(isReplyKind('group_reply'),true);
  assert.equal(isReplyKind('reply'),true);
  assert.equal(isReplyKind('discussion'),false);
  assert.equal(isGroupConversationKind('reply'),false);
  assert.equal(isGroupConversationKind('group_reply'),true);
  assert.equal(isGroupConversationKind('discussion'),true);
});

test('one phone combines neurological and rehabilitation permissions without bot or administrative escalation',()=>{
  const dual={role:'neurologist',roles:['neurologist','rehab1_physician']};
  assert.equal(canSendGroup(dual,'orit','review'),true);
  assert.equal(canSendGroup(dual,'rehab2','review'),true);
  assert.equal(canSendGroup(dual,'rehab1','discussion'),true);
  assert.equal(canSendGroup(dual,'orit','admission'),false);
  for(const bad of [{roles:['neurologist']},{role:null,roles:['neurologist']},[],['neurologist','neurologist'],['bot','neurologist'],['admin','rehab1_physician'],['cardiologist','neurologist'],['intensivist','rehab1_physician'],{role:'neurologist',roles:['rehab1_physician']},{role:'neurologist',roles:['rehab1_physician','neurologist']},{role:'neurologist',roles:null},{role:'neurologist',roles:['neurologist','unknown']}]){
    assert.equal(canSendGroup(bad,'rehab1','group_reply'),false,JSON.stringify(bad));
    assert.equal(canSendGroup(bad,'orit','review'),false,JSON.stringify(bad));
  }
});
