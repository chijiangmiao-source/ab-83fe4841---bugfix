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

test('跨代保留签名者：后续候选只改自身待签证据，已激活检查点历史不可变', () => {
  // 二钥二门限设备域：原成员 A、B。
  const A = genKey();
  const B = genKey();
  const C = genKey();
  const D = genKey();
  const T = (n) => `2026-10-06T00:0${n}:00.000Z`;

  const created = rotation.createDomain(
    freshState(),
    { name: '跨代域', publicKeys: [B.publicKey, A.publicKey], threshold: 2 },
    T(0),
  );
  let s = created.state;
  const id = created.result.id;
  const genesisDigest = created.result.headDigest;

  // 第一轮：新密钥集 [A, C] —— 保留一名原父成员 A。
  const r1 = rotation.createRotation(
    s,
    id,
    { rotationId: 'round-1', parentDigest: genesisDigest, publicKeys: [A.publicKey, C.publicKey], threshold: 2 },
    T(1),
  );
  s = r1.state;
  const rot1 = r1.result.rotation;
  const msg1 = rotation.authorizationMessage(rot1);
  const sigA1 = sign(A.privateKey, msg1);
  const sigB1 = sign(B.privateKey, msg1);

  // 第一轮由两名原成员 A、B 分两批完成有效签名。
  s = rotation.submitSignatures(s, id, 'round-1', [{ publicKey: A.publicKey, signature: sigA1 }], T(2)).state;
  const done1 = rotation.submitSignatures(
    s,
    id,
    'round-1',
    [{ publicKey: B.publicKey, signature: sigB1 }],
    T(3),
  );
  assert.equal(done1.result.activated, true);
  s = done1.state;
  const gen1Digest = rot1.digest;

  // 第二轮候选以第一轮链头为父，新密钥集 [A, D] —— 仍包含被保留的成员 A；
  // 另建一个同父竞争候选，用于验证拒绝结论不被恢复改动。
  s = rotation.createRotation(
    s,
    id,
    { rotationId: 'round-2', parentDigest: gen1Digest, publicKeys: [A.publicKey, D.publicKey], threshold: 2 },
    T(4),
  ).state;
  s = rotation.createRotation(
    s,
    id,
    { rotationId: 'round-2-alt', parentDigest: gen1Digest, publicKeys: [C.publicKey, D.publicKey], threshold: 2 },
    T(4),
  ).state;
  const rot2 = s.domains[id].rotations['round-2'];
  const msg2 = rotation.authorizationMessage(rot2);
  const sigA2 = sign(A.privateKey, msg2);

  // 第二轮只提交被保留成员 A 对第二轮规范消息的首个有效签名（1/2，未达门限）。
  const one = rotation.submitSignatures(
    s,
    id,
    'round-2',
    [{ publicKey: A.publicKey, signature: sigA2 }],
    T(5),
  );
  assert.equal(one.result.results[0].status, 'accepted');
  assert.equal(one.result.activated, false);
  assert.equal(one.result.signers, 1);
  s = one.state;

  // 读取历史：第一轮检查点证据必须仍是当时针对第一轮候选、父摘要、密钥集的签名，
  // 签名内容与接收时间都不得被第二轮收集动作改写。
  const dom = s.domains[id];
  assert.equal(dom.headDigest, gen1Digest, '第二轮未达门限，链头必须停在第一轮');
  assert.equal(dom.generation, 1);
  assert.ok(!('signerEvidence' in dom), '域内不应再存在按公钥跨代索引的证据表');
  const cp1 = dom.checkpoints[gen1Digest];
  const ev1 = Object.fromEntries(cp1.evidence.map((e) => [e.publicKey, e]));
  assert.equal(ev1[A.publicKey].signature, sigA1, '第一轮 A 的证据被第二轮签名污染');
  assert.equal(ev1[A.publicKey].receivedAt, T(2), '第一轮 A 证据的接收时间被改写');
  assert.equal(ev1[B.publicKey].signature, sigB1);
  assert.equal(ev1[B.publicKey].receivedAt, T(3));
  // 第一轮两份证据仍只验证第一轮固定的授权消息。
  assert.ok(rotation.verifyAuthorization(msg1, sigA1, A.publicKey));
  assert.ok(rotation.verifyAuthorization(msg1, ev1[A.publicKey].signature, A.publicKey));
  assert.ok(rotation.verifyAuthorization(msg1, ev1[B.publicKey].signature, B.publicKey));
  assert.ok(
    !rotation.verifyAuthorization(msg2, ev1[A.publicKey].signature, A.publicKey),
    '第一轮证据不可能通过第二轮消息验签',
  );
  // 链头视图读到的也是不可变历史。
  const head = rotation.headView(dom);
  assert.equal(head.digest, gen1Digest);
  assert.equal(
    head.evidence.find((e) => e.publicKey === A.publicKey).signature,
    sigA1,
    '链头视图中的第一轮证据被污染',
  );
  // 后续候选只改变自身的待签证据。
  const pending2 = dom.rotations['round-2'];
  assert.equal(pending2.status, 'pending');
  assert.equal(pending2.signatures.length, 1);
  assert.equal(pending2.signatures[0].signature, sigA2);
  assert.equal(pending2.signatures[0].receivedAt, T(5));
  assert.equal(dom.rotations['round-2-alt'].status, 'pending');

  // 重复签名处理不受影响：重传 A 的第二轮签名仍被去重且状态引用不变。
  const dup = rotation.submitSignatures(
    s,
    id,
    'round-2',
    [{ publicKey: A.publicKey, signature: sigA2 }],
    T(5),
  );
  assert.equal(dup.result.results[0].code, 'duplicate_signature');
  assert.equal(dup.state, s);
});

test('重启恢复：已被旧版本跨代污染的持久化历史安全修复，链头/待签候选/拒因/去重均不变', async () => {
  const A = genKey();
  const B = genKey();
  const C = genKey();
  const D = genKey();
  const T = (n) => `2026-10-06T01:0${n}:00.000Z`;

  // 先在纯逻辑里构造到“第二轮仅 A 一票”的状态（与上一用例相同的授权形态）。
  const created = rotation.createDomain(
    freshState(),
    { name: '恢复域', publicKeys: [B.publicKey, A.publicKey], threshold: 2 },
    T(0),
  );
  let s = created.state;
  const id = created.result.id;
  const genesisDigest = created.result.headDigest;
  const r1 = rotation.createRotation(
    s,
    id,
    { rotationId: 'round-1', parentDigest: genesisDigest, publicKeys: [A.publicKey, C.publicKey], threshold: 2 },
    T(1),
  );
  s = r1.state;
  const rot1 = r1.result.rotation;
  const msg1 = rotation.authorizationMessage(rot1);
  const sigA1 = sign(A.privateKey, msg1);
  const sigB1 = sign(B.privateKey, msg1);
  s = rotation.submitSignatures(s, id, 'round-1', [{ publicKey: A.publicKey, signature: sigA1 }], T(2)).state;
  s = rotation.submitSignatures(s, id, 'round-1', [{ publicKey: B.publicKey, signature: sigB1 }], T(3)).state;
  const gen1Digest = rot1.digest;
  s = rotation.createRotation(
    s,
    id,
    { rotationId: 'round-2', parentDigest: gen1Digest, publicKeys: [A.publicKey, D.publicKey], threshold: 2 },
    T(4),
  ).state;
  s = rotation.createRotation(
    s,
    id,
    { rotationId: 'round-2-alt', parentDigest: gen1Digest, publicKeys: [C.publicKey, D.publicKey], threshold: 2 },
    T(4),
  ).state;
  const rot2 = s.domains[id].rotations['round-2'];
  const msg2 = rotation.authorizationMessage(rot2);
  const sigA2 = sign(A.privateKey, msg2);
  s = rotation.submitSignatures(s, id, 'round-2', [{ publicKey: A.publicKey, signature: sigA2 }], T(5)).state;
  const sigC2 = sign(C.privateKey, msg2);

  // 干净状态落盘后重开应原样加载（无修复）。
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rotation-recover-'));
  const file = path.join(dir, 'state.json');
  const bootstrap = new Store(file);
  bootstrap.load();
  bootstrap.state = s;
  bootstrap._persist(s);
  const cleanReload = new Store(file);
  cleanReload.load();
  assert.deepEqual(cleanReload.state, s);

  // 模拟旧版本持久化下来的污染磁盘：第二轮收签把第一轮检查点中 A 的证据
  // 回写为第二轮签名（签名与接收时间都变了），并留下按公钥索引的证据表。
  const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  const cd = raw.domains[id];
  cd.checkpoints[gen1Digest].evidence = cd.checkpoints[gen1Digest].evidence.map((e) =>
    e.publicKey === A.publicKey
      ? { publicKey: A.publicKey, signature: sigA2, receivedAt: T(5) }
      : e,
  );
  cd.signerEvidence = {
    [A.publicKey]: { publicKey: A.publicKey, signature: sigA2, receivedAt: T(5) },
    [B.publicKey]: { publicKey: B.publicKey, signature: sigB1, receivedAt: T(3) },
  };
  fs.writeFileSync(file, `${JSON.stringify(raw, null, 2)}\n`);

  // 重开（重启）：历史证据安全恢复为可验证的原始内容。
  const store = new Store(file);
  store.load();
  const rd = store.state.domains[id];
  assert.equal(rd.headDigest, gen1Digest, '恢复不得改变活动链头');
  assert.equal(rd.generation, 1);
  assert.deepEqual(rd.keys, rot1.keys, '恢复不得改变当前密钥集');
  assert.equal(rd.threshold, 2);
  assert.ok(!('signerEvidence' in rd), '恢复应移除跨代证据索引表');
  const rcp1 = rd.checkpoints[gen1Digest];
  const rev1 = Object.fromEntries(rcp1.evidence.map((e) => [e.publicKey, e]));
  assert.equal(rev1[A.publicKey].signature, sigA1, 'A 的第一轮签名应从轮换记录恢复');
  assert.equal(rev1[A.publicKey].receivedAt, T(2), 'A 的第一轮接收时间应一并恢复');
  assert.equal(rev1[B.publicKey].signature, sigB1);
  assert.equal(rev1[B.publicKey].receivedAt, T(3));
  assert.ok(rotation.verifyAuthorization(msg1, rev1[A.publicKey].signature, A.publicKey));
  assert.ok(rotation.verifyAuthorization(msg1, rev1[B.publicKey].signature, B.publicKey));
  assert.ok(!rotation.verifyAuthorization(msg2, rev1[A.publicKey].signature, A.publicKey));
  // 当前待签候选及其自身证据、竞争候选状态均不被恢复改动。
  assert.equal(rd.rotations['round-2'].status, 'pending');
  assert.equal(rd.rotations['round-2'].signatures.length, 1);
  assert.equal(rd.rotations['round-2'].signatures[0].signature, sigA2);
  assert.equal(rd.rotations['round-2'].signatures[0].receivedAt, T(5));
  assert.equal(rd.rotations['round-2-alt'].status, 'pending');

  // 再次重开状态稳定（修复只做一次，之后逐字节稳定）。
  const secondReload = new Store(file);
  secondReload.load();
  assert.deepEqual(secondReload.state, store.state);

  // 恢复后重复签名仍被去重；补齐 C 的签名完成第二轮：链头前进、竞争候选被取代，
  // 而第一轮历史证据保持不变；第二轮检查点固化自己这一代的两份证据。
  const dupAgain = await store.commit((st) =>
    rotation.submitSignatures(st, id, 'round-2', [{ publicKey: A.publicKey, signature: sigA2 }], T(5)),
  );
  assert.equal(dupAgain.results[0].code, 'duplicate_signature');
  const finish = await store.commit((st) =>
    rotation.submitSignatures(st, id, 'round-2', [{ publicKey: C.publicKey, signature: sigC2 }], T(6)),
  );
  assert.equal(finish.activated, true);
  const fd = store.state.domains[id];
  assert.equal(fd.headDigest, rot2.digest);
  assert.equal(fd.generation, 2);
  assert.equal(fd.rotations['round-2-alt'].status, 'superseded', '竞争候选的拒绝结论必须保留');
  assert.match(fd.rotations['round-2-alt'].rejectedReason, /取代/);
  const stillCp1 = fd.checkpoints[gen1Digest];
  assert.equal(
    stillCp1.evidence.find((e) => e.publicKey === A.publicKey).signature,
    sigA1,
    '完成第二轮后第一轮历史仍不得改变',
  );
  const cp2 = fd.checkpoints[rot2.digest];
  const ev2 = Object.fromEntries(cp2.evidence.map((e) => [e.publicKey, e]));
  assert.equal(ev2[A.publicKey].signature, sigA2);
  assert.equal(ev2[A.publicKey].receivedAt, T(5));
  assert.equal(ev2[C.publicKey].signature, sigC2);
  assert.equal(ev2[C.publicKey].receivedAt, T(6));
  assert.ok(rotation.verifyAuthorization(msg2, ev2[A.publicKey].signature, A.publicKey));
  assert.ok(rotation.verifyAuthorization(msg2, ev2[C.publicKey].signature, C.publicKey));

  const finalReload = new Store(file);
  finalReload.load();
  assert.deepEqual(finalReload.state, store.state, '第二轮完成后重启状态一致');

  // 无法验证且无可靠来源的历史不得被静默接受。
  const unrecoverable = JSON.parse(JSON.stringify(raw));
  const ud = unrecoverable.domains[id];
  ud.rotations['round-1'].signatures = ud.rotations['round-1'].signatures.map((x) =>
    x.publicKey === A.publicKey ? { ...x, signature: 'f'.repeat(128) } : x,
  );
  assert.throws(() => rotation.recoverDomainHistory(ud), (e) => e.code === 'history_corrupt');
});
