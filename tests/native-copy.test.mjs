import test from 'node:test';
import assert from 'node:assert/strict';
import {copyRenderedLink} from '../docs/sharing.mjs';

function nativeFixture(outcome = true) {
  const oldRanges = [{id:'first'}, {id:'second'}];
  for (const range of oldRanges) range.cloneRange = () => range;
  let currentRanges = [...oldRanges], focused = 0, commandCount = 0, copiedNode;
  const anchor = {href:'https://viewer.example/#pso=PSO1.r.s.c.sig', textContent:'Новый пациент', isConnected:true};
  const selection = {
    get rangeCount() { return currentRanges.length; },
    getRangeAt(index) { return currentRanges[index]; },
    removeAllRanges() { currentRanges = []; },
    addRange(range) { currentRanges.push(range); }
  };
  const doc = {
    activeElement:{focus() { focused++; }},
    createRange() { return {selectNode(node) { this.node = node; }}; },
    execCommand(command) {
      assert.equal(command, 'copy'); commandCount++;
      copiedNode = currentRanges[0]?.node;
      if (outcome === 'throw') throw new Error('Clipboard unavailable');
      return outcome;
    }
  };
  return {anchor, doc, selection, oldRanges, ranges:() => currentRanges,
    focused:() => focused, commandCount:() => commandCount, copiedNode:() => copiedNode};
}

test('native selection copy restores prior ranges and focus on success, false return and exception', () => {
  for (const outcome of [true, false, 'throw']) {
    const fixture = nativeFixture(outcome);
    assert.equal(copyRenderedLink(fixture.anchor, fixture.doc, fixture.selection), outcome === true);
    assert.equal(fixture.commandCount(), 1);
    assert.equal(fixture.copiedNode(), fixture.anchor, 'Select the anchor itself so its href is retained');
    assert.deepEqual(fixture.ranges(), fixture.oldRanges);
    assert.equal(fixture.focused(), 1);
  }
});

test('unavailable native copy fails closed without disturbing selection or throwing', () => {
  const fixture = nativeFixture();
  assert.equal(copyRenderedLink(null, fixture.doc, fixture.selection), false);
  assert.equal(copyRenderedLink(fixture.anchor, {}, fixture.selection), false);
  assert.equal(copyRenderedLink(fixture.anchor, fixture.doc, null), false);
  assert.deepEqual(fixture.ranges(), fixture.oldRanges);
  assert.equal(fixture.commandCount(), 0);
});
