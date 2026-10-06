'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const rotation = require('../src/rotation');
const { Store } = require('../src/store');

const NOW = '2026-10-06T00:00:00.000Z';

function genKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
  return { publicKey: pub, privateKey };
}

function sign(privateKey, message) {
  return crypto.sign(null, Buffer.from(message, 'utf8'), privateKey).toString('hex');
}

function freshState() {
  return { version: 1, domains: {} };
}

function makeDomain(state, keys, threshold) {
  const { state: s2, result } = rotation.createDomain(
    state,
    { name: '测试域', publicKeys: keys.map((k) => k.publicKey), threshold },
    NOW,
  );
  return { state: s2, domain: result };
}

test('密钥集校验：排序、去重、数量与门限边界', () => {
  const a = 'a'.repeat(64);
  const b = 'B'.repeat(64); // 大写应归一化
  const c = 'c'.repeat(64);
  const { keys, threshold } = rotation.validateKeySet([c, a, b], 2);
  assert.deepEqual(keys, ['a'.repeat(64), 'b'.repeat(64), 'c'.repeat(64)]);
  assert.equal(threshold, 2);

  assert.throws(() => rotation.validateKeySet([a, a], 1), /重复/);
  assert.throws(() => rotation.validateKeySet([a], 1), (e) => e.code === 'invalid_key_set');
  assert.throws(() => rotation.validateKeySet([a, b, c, 'd'.repeat(64), 'e'.repeat(64), 'f'.repeat(64)], 1), /2–5/);
  assert.throws(() => rotation.validateKeySet([a, 'zz'.repeat(32)], 1), /十六进制/);
  assert.throws(() => rotation.validateKeySet([a, b], 0), (e) => e.code === 'invalid_threshold');
  assert.throws(() => rotation.validateKeySet([a, b], 3), (e) => e.code === 'invalid_threshold');
  assert.throws(() => rotation.validateKeySet([a, b], 1.5), (e) => e.code === 'invalid_threshold');
});

test('检查点摘要与授权消息：规范化、确定性、与输入顺序无关', () => {
  const base = {
    domainId: 'dom-1',
    rotationId: 'rot-1',
    parentDigest: '0'.repeat(64),
    generation: 1,
    threshold: 2,
    keys: rotation.sortKeys(['b'.repeat(64), 'a'.repeat(64)]),
  };
  const same = { ...base, keys: rotation.sortKeys(['a'.repeat(64), 'b'.repeat(64)]) };
  assert.equal(rotation.checkpointDigest(base), rotation.checkpointDigest(same));
  assert.match(rotation.checkpointDigest(base), /^[0-9a-f]{64}$/);

  const message = rotation.authorizationMessage(base);
  assert.ok(message.includes('parent=' + '0'.repeat(64)));
  assert.ok(message.includes('keys=' + 'a'.repeat(64) + ',' + 'b'.repeat(64)));
  // 任一字段变化都会改变待签消息（篡改载荷必然验签失败）。
  assert.notEqual(rotation.authorizationMessage({ ...base, threshold: 3 }), message);
  assert.notEqual(rotation.authorizationMessage({ ...base, rotationId: 'rot-2' }), message);
  assert.notEqual(rotation.authorizationMessage({ ...base, parentDigest: '1'.repeat(64) }), message);
});

test('创建设备域：创世检查点立即激活并成为链头', () => {
  const keys = [genKey(), genKey()];
  const { state, domain } = makeDomain(freshState(), keys, 2);
  assert.equal(domain.generation, 0);
  assert.equal(domain.headDigest, Object.keys(domain.checkpoints)[0]);
  const genesis = domain.checkpoints[domain.headDigest];
  assert.equal(genesis.status, 'activated');
  assert.equal(genesis.parentDigest, '0'.repeat(64));
  assert.deepEqual(genesis.keys, rotation.sortKeys(keys.map((k) => k.publicKey)));
  assert.ok(state.domains[domain.id]);
});

test('创建轮换：错误父摘要被拒且不改变状态；同标识幂等；冲突载荷被拒', () => {
  const keys = [genKey(), genKey()];
  const { state, domain } = makeDomain(freshState(), keys, 2);
  const next = [genKey(), genKey()];

  assert.throws(
    () => rotation.createRotation(state, domain.id, { rotationId: 'r1', parentDigest: 'f'.repeat(64), publicKeys: next.map((k) => k.publicKey), threshold: 2 }, NOW),
    (e) => e.code === 'wrong_parent_digest',
  );

  const input = { rotationId: 'r1', parentDigest: domain.headDigest, publicKeys: next.map((k) => k.publicKey), threshold: 2 };
  const first = rotation.createRotation(state, domain.id, input, NOW);
  assert.equal(first.result.created, true);
  assert.equal(first.result.rotation.generation, 1);
  assert.equal(first.result.rotation.parentDigest, domain.headDigest);

  const again = rotation.createRotation(first.state, domain.id, input, NOW + 'x');
  assert.equal(again.result.created, false);
  assert.equal(again.state, first.state, '幂等创建不应改变状态');

  assert.throws(
    () => rotation.createRotation(first.state, domain.id, { ...input, threshold: 1 }, NOW),
    (e) => e.code === 'conflicting_rotation',
  );
});

test('签名提交：非成员、篡改载荷、重复签名均被拒且不改变状态', () => {
  const members = [genKey(), genKey()];
  const outsider = genKey();
  const { state, domain } = makeDomain(freshState(), members, 2);
  const next = [genKey(), genKey()];
  const created = rotation.createRotation(
    state,
    domain.id,
    { rotationId: 'r1', parentDigest: domain.headDigest, publicKeys: next.map((k) => k.publicKey), threshold: 2 },
    NOW,
  );
  const rot = created.result.rotation;
  const message = rotation.authorizationMessage(rot);

  // 非父密钥成员
  const notMember = rotation.submitSignatures(
    created.state, domain.id, 'r1',
    [{ publicKey: outsider.publicKey, signature: sign(outsider.privateKey, message) }],
    NOW,
  );
  assert.equal(notMember.result.results[0].code, 'not_parent_member');
  assert.equal(notMember.state, created.state);

  // 篡改载荷：签的是别的消息
  const tampered = rotation.submitSignatures(
    created.state, domain.id, 'r1',
    [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, message + '\nextra=1') }],
    NOW,
  );
  assert.equal(tampered.result.results[0].code, 'invalid_signature');
  assert.equal(tampered.state, created.state);

  // 合法签名被接受
  const one = rotation.submitSignatures(
    created.state, domain.id, 'r1',
    [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, message) }],
    NOW,
  );
  assert.equal(one.result.results[0].status, 'accepted');
  assert.equal(one.result.activated, false);
  assert.equal(one.result.signers, 1);

  // 重传同一签名 → 重复拒因，状态不变
  const dup = rotation.submitSignatures(
    one.state, domain.id, 'r1',
    [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, message) }],
    NOW,
  );
  assert.equal(dup.result.results[0].code, 'duplicate_signature');
  assert.equal(dup.state, one.state);

  // 同批内重复也只计一次
  const sameBatch = rotation.submitSignatures(
    created.state, domain.id, 'r1',
    [
      { publicKey: members[0].publicKey, signature: sign(members[0].privateKey, message) },
      { publicKey: members[0].publicKey, signature: sign(members[0].privateKey, message) },
    ],
    NOW,
  );
  assert.equal(sameBatch.result.results[0].status, 'accepted');
  assert.equal(sameBatch.result.results[1].code, 'duplicate_signature');
  assert.equal(sameBatch.result.signers, 1);
});

test('达到父门限即激活：链头前进、证据完整、竞争候选被取代、迟到签名被拒', () => {
  const members = [genKey(), genKey()];
  const { state, domain } = makeDomain(freshState(), members, 2);
  const nextA = [genKey(), genKey()];
  const nextB = [genKey(), genKey(), genKey()];

  const s1 = rotation.createRotation(state, domain.id, { rotationId: 'win', parentDigest: domain.headDigest, publicKeys: nextA.map((k) => k.publicKey), threshold: 2 }, NOW).state;
  const s2 = rotation.createRotation(s1, domain.id, { rotationId: 'lose', parentDigest: domain.headDigest, publicKeys: nextB.map((k) => k.publicKey), threshold: 2 }, NOW).state;

  const rotWin = s2.domains[domain.id].rotations.win;
  const msgWin = rotation.authorizationMessage(rotWin);
  const rotLose = s2.domains[domain.id].rotations.lose;
  const msgLose = rotation.authorizationMessage(rotLose);

  // 两个候选各收一票（竞争提交进行中）
  const s3 = rotation.submitSignatures(s2, domain.id, 'win', [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, msgWin) }], NOW).state;
  const s4 = rotation.submitSignatures(s3, domain.id, 'lose', [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, msgLose) }], NOW).state;

  // win 达到门限 → 激活；lose 在同一迁移中被取代
  const done = rotation.submitSignatures(s4, domain.id, 'win', [{ publicKey: members[1].publicKey, signature: sign(members[1].privateKey, msgWin) }], NOW);
  assert.equal(done.result.activated, true);
  const after = done.state.domains[domain.id];
  assert.equal(after.headDigest, rotWin.digest);
  assert.equal(after.generation, 1);
  assert.deepEqual(after.keys, rotWin.keys);
  const headCp = after.checkpoints[after.headDigest];
  assert.equal(headCp.evidence.length, 2);
  assert.deepEqual(headCp.evidence.map((e) => e.publicKey).sort(), members.map((m) => m.publicKey).sort());
  assert.equal(after.rotations.lose.status, 'superseded');
  assert.match(after.rotations.lose.rejectedReason, /取代/);

  // 迟到的签名（激活后补签）被拒，链头不变
  assert.throws(
    () => rotation.submitSignatures(done.state, domain.id, 'win', [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, msgWin) }], NOW),
    (e) => e.code === 'rotation_already_activated',
  );
  assert.throws(
    () => rotation.submitSignatures(done.state, domain.id, 'lose', [{ publicKey: members[1].publicKey, signature: sign(members[1].privateKey, msgLose) }], NOW),
    (e) => e.code === 'rotation_superseded',
  );
  assert.equal(done.state.domains[domain.id].headDigest, rotWin.digest);

  // 激活后用旧父摘要创建竞争候选 → 错误父摘要
  assert.throws(
    () => rotation.createRotation(done.state, domain.id, { rotationId: 'late', parentDigest: domain.headDigest, publicKeys: nextA.map((k) => k.publicKey), threshold: 2 }, NOW),
    (e) => e.code === 'wrong_parent_digest',
  );
});

test('持久化：提交后重载状态一致；并发补签只收敛为一个活动检查点', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rotation-store-'));
  const file = path.join(dir, 'state.json');
  const store = new Store(file);
  store.load();

  const members = [genKey(), genKey()];
  const domain = await store.commit((s) => rotation.createDomain(s, { name: '并发域', publicKeys: members.map((m) => m.publicKey), threshold: 2 }, NOW));
  const next = [genKey(), genKey()];
  await store.commit((s) => rotation.createRotation(s, domain.id, { rotationId: 'r1', parentDigest: domain.headDigest, publicKeys: next.map((k) => k.publicKey), threshold: 2 }, NOW));
  const rot = store.state.domains[domain.id].rotations.r1;
  const message = rotation.authorizationMessage(rot);

  // 并发提交两批签名 + 两批重传（乱序到达的补签与重传）
  const batch = (m) => [{ publicKey: m.publicKey, signature: sign(m.privateKey, message) }];
  const outcomes = await Promise.allSettled([
    store.commit((s) => rotation.submitSignatures(s, domain.id, 'r1', batch(members[0]), NOW)),
    store.commit((s) => rotation.submitSignatures(s, domain.id, 'r1', batch(members[1]), NOW)),
    store.commit((s) => rotation.submitSignatures(s, domain.id, 'r1', batch(members[0]), NOW)),
    store.commit((s) => rotation.submitSignatures(s, domain.id, 'r1', batch(members[1]), NOW)),
  ]);
  const fulfilled = outcomes.filter((o) => o.status === 'fulfilled').map((o) => o.value);
  const rejected = outcomes.filter((o) => o.status === 'rejected').map((o) => o.reason);
  assert.equal(fulfilled.filter((o) => o.activated).length, 1, '恰好一次提交触发激活');
  for (const late of rejected) assert.equal(late.code, 'rotation_already_activated', '激活后的重传应被拒');
  for (const f of fulfilled) {
    if (!f.activated) assert.ok(f.results.every((r) => r.status === 'rejected' || f.signers <= 2));
  }
  const finalDomain = store.state.domains[domain.id];
  assert.equal(finalDomain.headDigest, rot.digest);
  assert.equal(finalDomain.rotations.r1.signatures.length, 2, '重传被去重，仅两名签名者');
  assert.equal(finalDomain.checkpoints[rot.digest].evidence.length, 2);

  // 重载（模拟重启）后链头、检查点、证据完全一致
  const reloaded = new Store(file);
  reloaded.load();
  assert.deepEqual(reloaded.state, store.state);
  assert.ok(!fs.existsSync(`${file}.tmp`), '原子提交不残留临时文件');
});

test('持久化：竞争候选并发达标，磁盘上只有一个活动检查点', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rotation-race-'));
  const store = new Store(path.join(dir, 'state.json'));
  store.load();

  const members = [genKey(), genKey()];
  const domain = await store.commit((s) => rotation.createDomain(s, { name: '竞争域', publicKeys: members.map((m) => m.publicKey), threshold: 2 }, NOW));
  for (const rid of ['race-1', 'race-2']) {
    const keys = [genKey(), genKey()];
    await store.commit((s) => rotation.createRotation(s, domain.id, { rotationId: rid, parentDigest: domain.headDigest, publicKeys: keys.map((k) => k.publicKey), threshold: 2 }, NOW));
  }
  const dom = () => store.state.domains[domain.id];
  const msg = (rid) => rotation.authorizationMessage(dom().rotations[rid]);
  const fullBatch = (rid) => members.map((m) => ({ publicKey: m.publicKey, signature: sign(m.privateKey, msg(rid)) }));

  const results = await Promise.allSettled([
    store.commit((s) => rotation.submitSignatures(s, domain.id, 'race-1', fullBatch('race-1'), NOW)),
    store.commit((s) => rotation.submitSignatures(s, domain.id, 'race-2', fullBatch('race-2'), NOW)),
  ]);
  const fulfilled = results.filter((r) => r.status === 'fulfilled').map((r) => r.value);
  const rejected = results.filter((r) => r.status === 'rejected').map((r) => r.reason);
  assert.equal(fulfilled.filter((o) => o.activated).length, 1, '只有一个候选激活');
  assert.equal(rejected.length, 1);
  assert.equal(rejected[0].code, 'rotation_superseded');

  const finalDomain = dom();
  const activated = Object.values(finalDomain.rotations).filter((r) => r.status === 'activated');
  assert.equal(activated.length, 1);
  assert.equal(finalDomain.headDigest, activated[0].digest);
  assert.equal(Object.values(finalDomain.checkpoints).filter((c) => c.generation === 1).length, 1, '同代次只有一个活动检查点');
});

test('跨代轮换：后续候选收集签名不改写已激活检查点的历史证据', () => {
  const memberA = genKey(); // 跨代保留的签名者
  const memberB = genKey();
  const nextC = genKey();
  const nextD = genKey();
  const { state: s0, domain } = makeDomain(freshState(), [memberA, memberB], 2);

  // 第一轮：新密钥集保留 memberA；两名原成员分批完成有效签名
  const s1 = rotation.createRotation(
    s0,
    domain.id,
    { rotationId: 'gen-1', parentDigest: domain.headDigest, publicKeys: [nextC.publicKey, memberA.publicKey], threshold: 2 },
    NOW,
  ).state;
  const rot1 = s1.domains[domain.id].rotations['gen-1'];
  assert.ok(rot1.keys.includes(memberA.publicKey), '第一轮新密钥集应保留原父成员');
  const msg1 = rotation.authorizationMessage(rot1);
  const sigA1 = sign(memberA.privateKey, msg1);
  const sigB1 = sign(memberB.privateKey, msg1);
  const tA1 = '2026-10-06T01:00:00.000Z';
  const tB1 = '2026-10-06T01:01:00.000Z';
  const s2 = rotation.submitSignatures(s1, domain.id, 'gen-1', [{ publicKey: memberA.publicKey, signature: sigA1 }], tA1).state;
  const done1 = rotation.submitSignatures(s2, domain.id, 'gen-1', [{ publicKey: memberB.publicKey, signature: sigB1 }], tB1);
  assert.equal(done1.result.activated, true);
  const head1 = done1.state.domains[domain.id].headDigest;
  const evidence1 = structuredClone(done1.state.domains[domain.id].checkpoints[head1].evidence);
  assert.equal(evidence1.length, 2);

  // 第二轮：父密钥成员（第一轮的 {memberA, nextC}）仍包含被保留的 memberA；
  // 只提交 memberA 对第二轮规范待签消息的首个有效签名
  const s3 = rotation.createRotation(
    done1.state,
    domain.id,
    { rotationId: 'gen-2', parentDigest: head1, publicKeys: [nextD.publicKey, memberA.publicKey], threshold: 2 },
    NOW,
  ).state;
  const rot2 = s3.domains[domain.id].rotations['gen-2'];
  const msg2 = rotation.authorizationMessage(rot2);
  assert.notEqual(msg2, msg1, '两轮的规范待签消息必须不同');
  const sigA2 = sign(memberA.privateKey, msg2);
  const tA2 = '2026-10-06T02:00:00.000Z';
  const second = rotation.submitSignatures(s3, domain.id, 'gen-2', [{ publicKey: memberA.publicKey, signature: sigA2 }], tA2);
  assert.equal(second.result.activated, false);
  assert.equal(second.result.signers, 1);

  // 读取历史：第一轮检查点的两份证据未被改写，仍能验证其原始授权消息
  const after = second.state.domains[domain.id];
  assert.equal(after.headDigest, head1, '第二轮未达门限，链头不应前进');
  const cp1 = after.checkpoints[head1];
  assert.deepEqual(cp1.evidence, evidence1, '已激活检查点的证据（签名内容与接收时间）不得改变');
  const byKey = Object.fromEntries(cp1.evidence.map((e) => [e.publicKey, e]));
  assert.equal(byKey[memberA.publicKey].signature, sigA1);
  assert.equal(byKey[memberA.publicKey].receivedAt, tA1);
  assert.equal(byKey[memberB.publicKey].signature, sigB1);
  assert.equal(byKey[memberB.publicKey].receivedAt, tB1);
  for (const e of cp1.evidence) {
    assert.ok(rotation.verifyAuthorization(msg1, e.signature, e.publicKey), '第一代证据必须仍能验证其原始授权消息');
  }
  // 第一轮候选的签名记录同样不变
  assert.deepEqual(after.rotations['gen-1'].signatures, evidence1);
  // 第二轮候选自身的待签证据正常累积
  assert.deepEqual(after.rotations['gen-2'].signatures, [
    { publicKey: memberA.publicKey, signature: sigA2, receivedAt: tA2 },
  ]);
});

test('重启恢复：被改写的历史证据在加载时修复为可验证证据，其余状态不变', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rotation-repair-'));
  const file = path.join(dir, 'state.json');
  const store = new Store(file);
  store.load();

  const memberA = genKey(); // 跨代保留的签名者
  const memberB = genKey();
  const nextC = genKey();
  const nextD = genKey();
  const domain = await store.commit((s) =>
    rotation.createDomain(s, { name: '修复域', publicKeys: [memberA.publicKey, memberB.publicKey], threshold: 2 }, NOW),
  );
  await store.commit((s) =>
    rotation.createRotation(s, domain.id, { rotationId: 'gen-1', parentDigest: domain.headDigest, publicKeys: [memberA.publicKey, nextC.publicKey], threshold: 2 }, NOW),
  );
  await store.commit((s) =>
    rotation.createRotation(s, domain.id, { rotationId: 'gen-1-rival', parentDigest: domain.headDigest, publicKeys: [nextC.publicKey, nextD.publicKey], threshold: 2 }, NOW),
  );
  const rot1 = store.state.domains[domain.id].rotations['gen-1'];
  const msg1 = rotation.authorizationMessage(rot1);
  await store.commit((s) =>
    rotation.submitSignatures(s, domain.id, 'gen-1', [{ publicKey: memberA.publicKey, signature: sign(memberA.privateKey, msg1) }], '2026-10-06T01:00:00.000Z'),
  );
  await store.commit((s) =>
    rotation.submitSignatures(s, domain.id, 'gen-1', [{ publicKey: memberB.publicKey, signature: sign(memberB.privateKey, msg1) }], '2026-10-06T01:01:00.000Z'),
  );
  const head1 = store.state.domains[domain.id].headDigest;
  await store.commit((s) =>
    rotation.createRotation(s, domain.id, { rotationId: 'gen-2', parentDigest: head1, publicKeys: [memberA.publicKey, nextD.publicKey], threshold: 2 }, NOW),
  );
  const rot2 = store.state.domains[domain.id].rotations['gen-2'];
  const msg2 = rotation.authorizationMessage(rot2);
  const sigA2 = sign(memberA.privateKey, msg2);
  await store.commit((s) =>
    rotation.submitSignatures(s, domain.id, 'gen-2', [{ publicKey: memberA.publicKey, signature: sigA2 }], '2026-10-06T02:00:00.000Z'),
  );

  const healthy = structuredClone(store.state.domains[domain.id]);
  assert.equal(healthy.rotations['gen-1-rival'].status, 'superseded');
  assert.equal(healthy.rotations['gen-2'].status, 'pending');

  // 模拟历史版本缺陷留下的受损持久化状态：第一代检查点中 memberA 的证据
  // 被其第二轮签名覆盖，并遗留 signerEvidence 索引
  const corrupted = JSON.parse(fs.readFileSync(file, 'utf8'));
  const corruptedCp1 = corrupted.domains[domain.id].checkpoints[head1];
  corruptedCp1.evidence = corruptedCp1.evidence.map((e) =>
    e.publicKey === memberA.publicKey
      ? { publicKey: memberA.publicKey, signature: sigA2, receivedAt: '2026-10-06T02:00:00.000Z' }
      : e,
  );
  corrupted.domains[domain.id].signerEvidence = {
    [memberA.publicKey]: { publicKey: memberA.publicKey, signature: sigA2, receivedAt: '2026-10-06T02:00:00.000Z' },
  };
  fs.writeFileSync(file, JSON.stringify(corrupted, null, 2) + '\n');

  // 重开（重启）：受损证据恢复为可验证的历史证据，且与健康状态逐项一致
  const reloaded = new Store(file);
  reloaded.load();
  const repaired = reloaded.state.domains[domain.id];
  assert.deepEqual(repaired, healthy, '修复后状态应与未受损状态一致');
  assert.equal(repaired.signerEvidence, undefined, '遗留的 signerEvidence 索引应被清理');
  assert.equal(repaired.headDigest, head1, '修复不得改变活动链头');
  assert.equal(repaired.rotations['gen-2'].status, 'pending', '修复不得改变当前待签候选');
  assert.equal(repaired.rotations['gen-1-rival'].status, 'superseded', '修复不得改变竞争候选的拒绝结论');
  for (const e of repaired.checkpoints[head1].evidence) {
    assert.ok(rotation.verifyAuthorization(msg1, e.signature, e.publicKey), '修复后的第一代证据必须可验证');
  }

  // 重复签名处理不受修复影响
  const dup = await reloaded.commit((s) =>
    rotation.submitSignatures(s, domain.id, 'gen-2', [{ publicKey: memberA.publicKey, signature: sigA2 }], '2026-10-06T03:00:00.000Z'),
  );
  assert.equal(dup.results[0].code, 'duplicate_signature');
  assert.equal(dup.signers, 1);

  // 修复结果已原子落盘：再次加载保持一致；健康状态无需修复（返回原引用）
  const again = new Store(file);
  again.load();
  assert.deepEqual(again.state.domains[domain.id], repaired);
  assert.equal(rotation.repairCheckpointEvidence(again.state), again.state);
});
