'use strict';

/**
 * 验收入口（compose 中的 verify 服务）：
 *   1. 运行轮换规则单元测试（node --test）；
 *   2. 运行构建检查（scripts/build-check.js）；
 *   3. 对运行中的服务做 HTTP 冒烟：
 *      - 创建二钥、门限为二的设备域；
 *      - 错误父摘要 / 篡改载荷 / 重复重传 / 非成员签名均被拒且链头不变；
 *      - 补齐两名有效签名后，接口可读回已激活链头与两份签名证据；
 *      - 页面渲染出相同结果；
 *      - 激活后的竞争候选与迟到补签被拒；
 *      - 并发竞争候选只收敛为一个活动检查点；
 *      - 跨代保留同一名签名者时，后续候选只改自身待签证据，
 *        已激活检查点的签名内容与接收时间始终不可变；
 *      - 应用重启后链头、历史检查点与签名证据保持一致；
 *      - 健康端点反映设备域状态。
 *   全部通过退出码 0，否则退出码 1。
 */

const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const APP_URL = (process.env.APP_URL || 'http://127.0.0.1:3000').replace(/\/+$/, '');

// Ed25519 SPKI DER 前缀（OID 1.3.101.112），后接 32 字节原始公钥。
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function verifySig(publicKeyHex, message, signatureHex) {
  try {
    const key = crypto.createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(publicKeyHex, 'hex')]),
      format: 'der',
      type: 'spki',
    });
    return crypto.verify(null, Buffer.from(message, 'utf8'), key, Buffer.from(signatureHex, 'hex'));
  } catch {
    return false;
  }
}

function countOccurrences(haystack, needle) {
  let count = 0;
  let at = haystack.indexOf(needle);
  while (at !== -1) {
    count += 1;
    at = haystack.indexOf(needle, at + needle.length);
  }
  return count;
}

let failures = 0;

function pass(name) {
  console.log(`  ✓ ${name}`);
}

function fail(name, detail) {
  failures += 1;
  console.error(`  ✗ ${name}`);
  if (detail) console.error(`    ${String(detail).split('\n').join('\n    ')}`);
}

async function step(name, fn) {
  try {
    await fn();
    pass(name);
  } catch (err) {
    fail(name, err && err.message ? err.message : err);
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) throw new Error(`${message}（期望 ${expected}，实际 ${actual}）`);
}

function runProcess(args, options = {}) {
  const res = spawnSync(process.execPath, args, { cwd: ROOT, encoding: 'utf8', timeout: 120000, ...options });
  return { status: res.status, output: `${res.stdout || ''}${res.stderr || ''}` };
}

async function api(method, urlPath, body) {
  const res = await fetch(`${APP_URL}${urlPath}`, {
    method,
    headers: body !== undefined ? { 'content-type': 'application/json' } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(10000),
  });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* 非 JSON 响应（如 HTML 页面） */
  }
  return { status: res.status, json, text };
}

function genKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
  return { publicKey: pub, privateKey };
}

function sign(key, message) {
  return crypto.sign(null, Buffer.from(message, 'utf8'), key.privateKey).toString('hex');
}

function flipHex(hex) {
  const last = hex.slice(-1);
  const flipped = last === '0' ? '1' : '0';
  return hex.slice(0, -1) + flipped;
}

async function waitForHealth(timeoutMs, predicate) {
  const deadline = Date.now() + timeoutMs;
  let lastError = '未收到响应';
  while (Date.now() < deadline) {
    try {
      const res = await api('GET', '/healthz');
      if (res.status === 200 && res.json && res.json.status === 'ok') {
        if (!predicate || predicate(res.json)) return res.json;
        lastError = '健康响应不满足等待条件';
      } else {
        lastError = `HTTP ${res.status}`;
      }
    } catch (err) {
      lastError = err.message;
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`等待服务健康超时：${lastError}`);
}

async function main() {
  console.log(`验收目标：${APP_URL}\n`);

  console.log('— 阶段 1：轮换规则单元测试 —');
  await step('node --test 轮换规则测试全部通过', async () => {
    const res = runProcess(['--test', 'test/']);
    assertEqual(res.status, 0, `单元测试失败：\n${res.output.trim().split('\n').slice(-30).join('\n')}`);
  });

  console.log('— 阶段 2：构建检查 —');
  await step('全部源码语法检查与模块加载检查通过', async () => {
    const res = runProcess([path.join('scripts', 'build-check.js')]);
    assertEqual(res.status, 0, `构建检查失败：\n${res.output}`);
  });

  console.log('— 阶段 3：HTTP 冒烟 —');
  let bootId = null;

  await step('服务健康且健康响应可用于反映设备域状态', async () => {
    const health = await waitForHealth(60000);
    assert(health.bootId && health.startedAt, '健康响应缺少 bootId/startedAt');
    assert(Array.isArray(health.domains), '健康响应缺少设备域列表');
    bootId = health.bootId;
  });

  // —— 验收主域：二钥、门限为二 ——
  const memberA = genKey();
  const memberB = genKey();
  const nextC = genKey();
  const nextD = genKey();
  const outsider = genKey();
  let domainId;
  let genesisHead;
  let rotationDigest;
  let sigA;
  let sigB;

  await step('创建二钥且门限为二的设备域（公钥乱序提交，服务端排序）', async () => {
    const res = await api('POST', '/api/domains', {
      name: '验收域-2of2',
      publicKeys: [memberB.publicKey, memberA.publicKey],
      threshold: 2,
    });
    assertEqual(res.status, 201, `创建设备域失败：${res.text}`);
    domainId = res.json.id;
    const expectedKeys = [memberA.publicKey, memberB.publicKey].sort();
    assert(JSON.stringify(res.json.keys) === JSON.stringify(expectedKeys), '密钥集未按规范排序');
    assertEqual(res.json.generation, 0, '创世代次应为 0');
    genesisHead = res.json.headDigest;
    assert(/^[0-9a-f]{64}$/.test(genesisHead), '链头摘要格式非法');
  });

  await step('健康响应反映新设备域状态', async () => {
    const health = (await api('GET', '/healthz')).json;
    const entry = health.domains.find((d) => d.id === domainId);
    assert(entry, '健康响应中找不到新设备域');
    assertEqual(entry.headDigest, genesisHead, '健康响应中的链头与接口不一致');
  });

  await step('错误父摘要的轮换候选被拒且链头不变', async () => {
    const res = await api('POST', `/api/domains/${domainId}/rotations`, {
      rotationId: 'bad-parent',
      parentDigest: 'ab'.repeat(32),
      publicKeys: [nextC.publicKey, nextD.publicKey],
      threshold: 2,
    });
    assertEqual(res.status, 422, `应返回 422：${res.text}`);
    assertEqual(res.json.error.code, 'wrong_parent_digest', '拒因应为 wrong_parent_digest');
    const head = (await api('GET', `/api/domains/${domainId}/head`)).json;
    assertEqual(head.digest, genesisHead, '链头被错误请求改变');
  });

  await step('创建轮换候选：固定父摘要、下一代次、排序后新公钥集、新门限', async () => {
    const res = await api('POST', `/api/domains/${domainId}/rotations`, {
      rotationId: 'rot-2026-001',
      parentDigest: genesisHead,
      publicKeys: [nextD.publicKey, nextC.publicKey],
      threshold: 2,
    });
    assertEqual(res.status, 201, `创建轮换失败：${res.text}`);
    rotationDigest = res.json.digest;
    assertEqual(res.json.parentDigest, genesisHead, '父摘要未固定为当前链头');
    assertEqual(res.json.generation, 1, '下一代次应为 1');
    assertEqual(res.json.threshold, 2, '新门限应为 2');
    assert(JSON.stringify(res.json.keys) === JSON.stringify([nextC.publicKey, nextD.publicKey].sort()), '新公钥集未排序');
    assertEqual(res.json.status, 'pending', '候选应处于待签状态');
  });

  await step('篡改载荷与非成员签名被拒且链头不变', async () => {
    const msgRes = await api('GET', `/api/domains/${domainId}/rotations/rot-2026-001/message`);
    assertEqual(msgRes.status, 200, '应能读取规范待签消息');
    const message = msgRes.json.message;
    assert(message.includes(`parent=${genesisHead}`), '待签消息未绑定父摘要');
    sigA = sign(memberA, message);
    sigB = sign(memberB, message);

    const tampered = await api('POST', `/api/domains/${domainId}/rotations/rot-2026-001/signatures`, {
      signatures: [{ publicKey: memberA.publicKey, signature: flipHex(sigA) }],
    });
    assertEqual(tampered.json.results[0].code, 'invalid_signature', '篡改签名应给出 invalid_signature');

    const wrongMessage = await api('POST', `/api/domains/${domainId}/rotations/rot-2026-001/signatures`, {
      signatures: [{ publicKey: memberA.publicKey, signature: sign(memberA, message + '\nforged=1') }],
    });
    assertEqual(wrongMessage.json.results[0].code, 'invalid_signature', '签错消息应给出 invalid_signature');

    const notMember = await api('POST', `/api/domains/${domainId}/rotations/rot-2026-001/signatures`, {
      signatures: [{ publicKey: outsider.publicKey, signature: sign(outsider, message) }],
    });
    assertEqual(notMember.json.results[0].code, 'not_parent_member', '非父成员应给出 not_parent_member');

    const head = (await api('GET', `/api/domains/${domainId}/head`)).json;
    assertEqual(head.digest, genesisHead, '被拒签名改变了链头');
    assertEqual(head.evidence.length, 0, '被拒签名不应产生证据');
  });

  await step('第一批签名（1/2）：候选保持待签，链头不提前生效', async () => {
    const res = await api('POST', `/api/domains/${domainId}/rotations/rot-2026-001/signatures`, {
      signatures: [{ publicKey: memberA.publicKey, signature: sigA }],
    });
    assertEqual(res.status, 200, `提交签名失败：${res.text}`);
    assertEqual(res.json.results[0].status, 'accepted', '有效签名应被接受');
    assertEqual(res.json.activated, false, '未达门限不应激活');
    assertEqual(res.json.signers, 1, '应记录 1 名签名者');
    const head = (await api('GET', `/api/domains/${domainId}/head`)).json;
    assertEqual(head.digest, genesisHead, '未达门限链头不应前进');
  });

  await step('重传同一签名：给出重复拒因且不改变状态', async () => {
    const res = await api('POST', `/api/domains/${domainId}/rotations/rot-2026-001/signatures`, {
      signatures: [{ publicKey: memberA.publicKey, signature: sigA }],
    });
    assertEqual(res.json.results[0].code, 'duplicate_signature', '重传应给出 duplicate_signature');
    assertEqual(res.json.signers, 1, '重传不应增加签名者');
    const head = (await api('GET', `/api/domains/${domainId}/head`)).json;
    assertEqual(head.digest, genesisHead, '重传不应改变链头');
  });

  await step('补齐第二名有效签名：同一提交中激活，接口读回链头与两份证据', async () => {
    const res = await api('POST', `/api/domains/${domainId}/rotations/rot-2026-001/signatures`, {
      signatures: [{ publicKey: memberB.publicKey, signature: sigB }],
    });
    assertEqual(res.json.results[0].status, 'accepted', '第二名签名应被接受');
    assertEqual(res.json.activated, true, '达到父门限应激活');
    assertEqual(res.json.headDigest, rotationDigest, '链头应前进到候选摘要');

    const head = (await api('GET', `/api/domains/${domainId}/head`)).json;
    assertEqual(head.digest, rotationDigest, '链头摘要与候选摘要不一致');
    assertEqual(head.generation, 1, '链头代次应为 1');
    assertEqual(head.threshold, 2, '新门限应生效');
    assert(JSON.stringify(head.keys) === JSON.stringify([nextC.publicKey, nextD.publicKey].sort()), '新密钥集应生效');
    assertEqual(head.evidence.length, 2, '应恰好有两份签名证据');
    const evidenceKeys = head.evidence.map((e) => e.publicKey).sort();
    assert(JSON.stringify(evidenceKeys) === JSON.stringify([memberA.publicKey, memberB.publicKey].sort()), '证据签名者不符');
    const evidenceSigs = Object.fromEntries(head.evidence.map((e) => [e.publicKey, e.signature]));
    assertEqual(evidenceSigs[memberA.publicKey], sigA, '成员 A 的签名证据不符');
    assertEqual(evidenceSigs[memberB.publicKey], sigB, '成员 B 的签名证据不符');
  });

  await step('激活后的迟到补签与竞争候选均被拒且链头不变', async () => {
    const late = await api('POST', `/api/domains/${domainId}/rotations/rot-2026-001/signatures`, {
      signatures: [{ publicKey: memberA.publicKey, signature: sigA }],
    });
    assertEqual(late.status, 409, `迟到补签应返回 409：${late.text}`);
    assertEqual(late.json.error.code, 'rotation_already_activated', '迟到补签应给出拒因');

    const staleParent = await api('POST', `/api/domains/${domainId}/rotations`, {
      rotationId: 'stale-competitor',
      parentDigest: genesisHead,
      publicKeys: [outsider.publicKey, genKey().publicKey],
      threshold: 2,
    });
    assertEqual(staleParent.status, 422, '旧父摘要的竞争候选应被拒');
    assertEqual(staleParent.json.error.code, 'wrong_parent_digest', '拒因应为 wrong_parent_digest');

    const head = (await api('GET', `/api/domains/${domainId}/head`)).json;
    assertEqual(head.digest, rotationDigest, '竞争请求改变了链头');
  });

  // —— 第二设备域：并发竞争只收敛为一个活动检查点 ——
  let domain2Id;
  let domain2Head;
  await step('并发竞争候选：恰好一个激活，其余被取代', async () => {
    const members = [genKey(), genKey()];
    const created = await api('POST', '/api/domains', {
      name: '并发竞争域',
      publicKeys: members.map((m) => m.publicKey),
      threshold: 2,
    });
    assertEqual(created.status, 201, `创建第二设备域失败：${created.text}`);
    domain2Id = created.json.id;
    const parent = created.json.headDigest;

    for (const rid of ['race-1', 'race-2']) {
      const keys = [genKey(), genKey()];
      const res = await api('POST', `/api/domains/${domain2Id}/rotations`, {
        rotationId: rid,
        parentDigest: parent,
        publicKeys: keys.map((k) => k.publicKey),
        threshold: 2,
      });
      assertEqual(res.status, 201, `创建竞争候选失败：${res.text}`);
    }
    const detail = (await api('GET', `/api/domains/${domain2Id}`)).json;
    const batch = (rid) => {
      const rot = detail.rotations.find((r) => r.rotationId === rid);
      return members.map((m) => ({ publicKey: m.publicKey, signature: sign(m, rot.message) }));
    };
    const [r1, r2] = await Promise.all([
      api('POST', `/api/domains/${domain2Id}/rotations/race-1/signatures`, { signatures: batch('race-1') }),
      api('POST', `/api/domains/${domain2Id}/rotations/race-2/signatures`, { signatures: batch('race-2') }),
    ]);
    const outcomes = [r1, r2];
    const activated = outcomes.filter((o) => o.status === 200 && o.json.activated === true);
    const superseded = outcomes.filter((o) => o.status === 409 && o.json.error && o.json.error.code === 'rotation_superseded');
    assertEqual(activated.length, 1, '并发下应恰好一个候选激活');
    assertEqual(superseded.length, 1, '落选候选应给出取代拒因');

    const after = (await api('GET', `/api/domains/${domain2Id}`)).json;
    const activeRotations = after.rotations.filter((r) => r.status === 'activated');
    assertEqual(activeRotations.length, 1, '应只有一个已激活轮换');
    assertEqual(after.headDigest, activeRotations[0].digest, '链头应等于唯一激活候选');
    const gen1 = after.checkpoints.filter((c) => c.generation === 1);
    assertEqual(gen1.length, 1, '同一代次应只有一个活动检查点');
    const loser = after.rotations.find((r) => r.status === 'superseded');
    assert(loser && loser.rejectedReason, '落选候选应记录拒因');
    domain2Head = after.headDigest;
  });

  // —— 第三设备域：跨代保留签名者，已激活历史必须不可变 ——
  let domain3Id;
  let gen0Head3;
  let gen1Head3;
  let gen2Head3;
  let msgRound1;
  let sigA1Cross;
  let sigB1Cross;
  let sigA2Cross;
  let sigC2Cross;
  const crossA = genKey();
  const crossB = genKey();
  const crossC = genKey();
  const crossD = genKey();

  await step('跨代场景：创建二钥二门限设备域（原成员 A、B）', async () => {
    const res = await api('POST', '/api/domains', {
      name: '跨代历史不可变域',
      publicKeys: [crossB.publicKey, crossA.publicKey],
      threshold: 2,
    });
    assertEqual(res.status, 201, `创建跨代设备域失败：${res.text}`);
    domain3Id = res.json.id;
    gen0Head3 = res.json.headDigest;
  });

  await step('跨代场景：第一轮新密钥集保留原成员 A，由两名原成员完成有效签名', async () => {
    const res = await api('POST', `/api/domains/${domain3Id}/rotations`, {
      rotationId: 'round-1',
      parentDigest: gen0Head3,
      publicKeys: [crossA.publicKey, crossC.publicKey],
      threshold: 2,
    });
    assertEqual(res.status, 201, `创建第一轮候选失败：${res.text}`);
    assertEqual(res.json.generation, 1, '第一轮代次应为 1');

    const msgRes = await api('GET', `/api/domains/${domain3Id}/rotations/round-1/message`);
    msgRound1 = msgRes.json.message;
    sigA1Cross = sign(crossA, msgRound1);
    sigB1Cross = sign(crossB, msgRound1);

    const first = await api('POST', `/api/domains/${domain3Id}/rotations/round-1/signatures`, {
      signatures: [{ publicKey: crossA.publicKey, signature: sigA1Cross }],
    });
    assertEqual(first.json.activated, false, '第一轮 1/2 不应提前激活');
    const second = await api('POST', `/api/domains/${domain3Id}/rotations/round-1/signatures`, {
      signatures: [{ publicKey: crossB.publicKey, signature: sigB1Cross }],
    });
    assertEqual(second.json.activated, true, '两名原成员签名齐备后第一轮应激活');
    gen1Head3 = second.json.headDigest;
    assertEqual(gen1Head3, res.json.digest, '第一轮链头应为候选摘要');
  });

  await step('跨代场景：第二轮候选父密钥成员仍含被保留的 A，另建同父竞争候选', async () => {
    const r2 = await api('POST', `/api/domains/${domain3Id}/rotations`, {
      rotationId: 'round-2',
      parentDigest: gen1Head3,
      publicKeys: [crossA.publicKey, crossD.publicKey],
      threshold: 2,
    });
    assertEqual(r2.status, 201, `创建第二轮候选失败：${r2.text}`);
    assertEqual(r2.json.generation, 2, '第二轮代次应为 2');
    assertEqual(r2.json.parentDigest, gen1Head3, '第二轮父摘要必须固定为第一轮链头');
    gen2Head3 = r2.json.digest;

    const alt = await api('POST', `/api/domains/${domain3Id}/rotations`, {
      rotationId: 'round-2-alt',
      parentDigest: gen1Head3,
      publicKeys: [crossC.publicKey, crossD.publicKey],
      threshold: 2,
    });
    assertEqual(alt.status, 201, `创建同父竞争候选失败：${alt.text}`);
  });

  await step('跨代场景：第二轮只补被保留成员 A 对第二轮规范消息的首个有效签名（1/2 未达门限）', async () => {
    const msgRes = await api('GET', `/api/domains/${domain3Id}/rotations/round-2/message`);
    const msgRound2 = msgRes.json.message;
    assert(msgRound2 !== msgRound1, '两轮规范待签消息必须不同');
    assert(msgRound2.includes(`parent=${gen1Head3}`), '第二轮消息应绑定第一轮链头');
    sigA2Cross = sign(crossA, msgRound2);

    const one = await api('POST', `/api/domains/${domain3Id}/rotations/round-2/signatures`, {
      signatures: [{ publicKey: crossA.publicKey, signature: sigA2Cross }],
    });
    assertEqual(one.status, 200, `提交第二轮签名失败：${one.text}`);
    assertEqual(one.json.results[0].status, 'accepted', 'A 对第二轮消息的首个有效签名应被接受');
    assertEqual(one.json.activated, false, '第二轮仅一票，不得激活');
    assertEqual(one.json.signers, 1, '第二轮应只有 1 名签名者');
    assertEqual(one.json.headDigest, gen1Head3, '第二轮未达门限，链头必须停在第一轮');

    // 重传 A 的第二轮签名：重复拒因，不改变状态。
    const dup = await api('POST', `/api/domains/${domain3Id}/rotations/round-2/signatures`, {
      signatures: [{ publicKey: crossA.publicKey, signature: sigA2Cross }],
    });
    assertEqual(dup.json.results[0].code, 'duplicate_signature', '第二轮重传应给出 duplicate_signature');
    assertEqual(dup.json.headDigest, gen1Head3, '重传不得改变链头');
  });

  await step('跨代场景：读取历史——第一轮两份证据仍是其原始授权消息的签名（详情/链头/页面一致）', async () => {
    const detail = (await api('GET', `/api/domains/${domain3Id}`)).json;
    assertEqual(detail.headDigest, gen1Head3, '域详情中的链头不得被第二轮待签改写');
    const cp1 = detail.checkpoints.find((c) => c.digest === gen1Head3);
    assert(cp1, '域详情中应能读取第一轮检查点');
    assertEqual(cp1.generation, 1);
    const ev1 = Object.fromEntries(cp1.evidence.map((e) => [e.publicKey, e]));
    assertEqual(ev1[crossA.publicKey].signature, sigA1Cross, '第一轮 A 的证据被第二轮签名污染（域详情）');
    assertEqual(ev1[crossB.publicKey].signature, sigB1Cross, '第一轮 B 的证据被改写（域详情）');
    assert(
      verifySig(crossA.publicKey, msgRound1, ev1[crossA.publicKey].signature),
      '第一轮 A 的证据不能验证第一轮固定授权消息',
    );
    assert(
      verifySig(crossB.publicKey, msgRound1, ev1[crossB.publicKey].signature),
      '第一轮 B 的证据不能验证第一轮固定授权消息',
    );

    const head = (await api('GET', `/api/domains/${domain3Id}/head`)).json;
    assertEqual(head.digest, gen1Head3, '链头仍应是第一轮检查点');
    const headEvA = head.evidence.find((e) => e.publicKey === crossA.publicKey);
    assertEqual(headEvA.signature, sigA1Cross, '链头视图中第一轮 A 的证据被第二轮候选签名污染');
    assert(verifySig(crossA.publicKey, msgRound1, headEvA.signature), '链头证据不能验证第一轮授权消息');

    // 第二轮候选自身的待签证据才应是新签名。
    const pending = detail.rotations.find((r) => r.rotationId === 'round-2');
    assertEqual(pending.status, 'pending');
    assertEqual(pending.signatures.length, 1);
    assertEqual(pending.signatures[0].signature, sigA2Cross, '第二轮候选自身的待签证据不符');

    // 运营页面同样不得把第一轮证据渲染成第二轮签名。
    const page = await api('GET', '/');
    assertEqual(page.status, 200, '页面应可访问');
    assert(page.text.includes(sigA1Cross), '页面未保留第一轮 A 的原始签名证据');
    assert(page.text.includes(sigB1Cross), '页面未保留第一轮 B 的原始签名证据');
    assertEqual(
      countOccurrences(page.text, sigA2Cross),
      1,
      '第二轮签名只应出现在待签候选明细中，绝不能回写到第一轮检查点',
    );
  });

  await step('跨代场景：补齐 C 的签名完成第二轮，竞争候选被取代，第一轮历史依旧不可变', async () => {
    const msgRes = await api('GET', `/api/domains/${domain3Id}/rotations/round-2/message`);
    sigC2Cross = sign(crossC, msgRes.json.message);
    const done = await api('POST', `/api/domains/${domain3Id}/rotations/round-2/signatures`, {
      signatures: [{ publicKey: crossC.publicKey, signature: sigC2Cross }],
    });
    assertEqual(done.json.activated, true, '第二轮达到父门限（A、C 均为第一轮密钥成员）应激活');
    assertEqual(done.json.headDigest, gen2Head3, '第二轮激活后链头应前进');

    const detail = (await api('GET', `/api/domains/${domain3Id}`)).json;
    assertEqual(detail.headDigest, gen2Head3);
    assertEqual(detail.generation, 2);
    assertEqual(detail.rotations.find((r) => r.rotationId === 'round-2').status, 'activated');
    const alt = detail.rotations.find((r) => r.rotationId === 'round-2-alt');
    assertEqual(alt.status, 'superseded', '同父竞争候选应被取代，拒绝结论须保留');
    assert(alt.rejectedReason, '竞争候选应记录拒因');
    const cp1 = detail.checkpoints.find((c) => c.digest === gen1Head3);
    const ev1 = Object.fromEntries(cp1.evidence.map((e) => [e.publicKey, e]));
    assertEqual(ev1[crossA.publicKey].signature, sigA1Cross, '第二轮完成后第一轮 A 的证据仍不得改变');
    assertEqual(ev1[crossB.publicKey].signature, sigB1Cross, '第二轮完成后第一轮 B 的证据仍不得改变');
    assert(verifySig(crossA.publicKey, msgRound1, ev1[crossA.publicKey].signature));
    assert(verifySig(crossB.publicKey, msgRound1, ev1[crossB.publicKey].signature));
    const cp2 = detail.checkpoints.find((c) => c.digest === gen2Head3);
    const ev2 = Object.fromEntries(cp2.evidence.map((e) => [e.publicKey, e]));
    assertEqual(ev2[crossA.publicKey].signature, sigA2Cross, '第二轮检查点应固化自己这一代 A 的签名');
    assertEqual(ev2[crossC.publicKey].signature, sigC2Cross, '第二轮检查点应固化 C 的签名');
  });

  // —— 重启一致性 ——
  let domain1Before;
  let domain2Before;
  let domain3Before;
  await step('应用重启后：链头、历史检查点与签名证据保持一致', async () => {
    domain1Before = (await api('GET', `/api/domains/${domainId}`)).json;
    domain2Before = (await api('GET', `/api/domains/${domain2Id}`)).json;
    domain3Before = (await api('GET', `/api/domains/${domain3Id}`)).json;

    const restart = await api('POST', '/api/admin/restart');
    assertEqual(restart.status, 202, `重启端点应返回 202：${restart.text}`);

    const health = await waitForHealth(60000, (h) => h.bootId !== bootId);
    assert(health.bootId !== bootId, '重启后 bootId 应变化（确为新进程）');

    const domain1After = (await api('GET', `/api/domains/${domainId}`)).json;
    const domain2After = (await api('GET', `/api/domains/${domain2Id}`)).json;
    assert(
      JSON.stringify(domain1After) === JSON.stringify(domain1Before),
      '验收域重启前后状态不一致（链头/检查点/证据丢失）',
    );
    assert(
      JSON.stringify(domain2After) === JSON.stringify(domain2Before),
      '并发域重启前后状态不一致（链头/检查点/证据丢失）',
    );
    const head = (await api('GET', `/api/domains/${domainId}/head`)).json;
    assertEqual(head.digest, rotationDigest, '重启后链头摘要变化');
    assertEqual(head.evidence.length, 2, '重启后签名证据份数变化');

    // 跨代域：重启后活动链头停在第二轮，第一/二轮证据逐字段不变，
    // 第一轮两份证据仍能验证第一轮固定授权消息；竞争候选拒绝结论保留。
    const d3 = (await api('GET', `/api/domains/${domain3Id}`)).json;
    assert(
      JSON.stringify(d3) === JSON.stringify(domain3Before),
      '跨代域重启前后状态不一致（历史证据被改写或丢失）',
    );
    assertEqual(d3.headDigest, gen2Head3, '重启后跨代域链头应停在第二轮');
    assertEqual(d3.generation, 2);
    const r1 = d3.checkpoints.find((c) => c.digest === gen1Head3);
    const r1ev = Object.fromEntries(r1.evidence.map((e) => [e.publicKey, e]));
    assertEqual(r1ev[crossA.publicKey].signature, sigA1Cross, '重启后第一轮 A 的证据被改变');
    assertEqual(r1ev[crossB.publicKey].signature, sigB1Cross, '重启后第一轮 B 的证据被改变');
    assert(
      verifySig(crossA.publicKey, msgRound1, r1ev[crossA.publicKey].signature),
      '重启后第一轮 A 的证据不能验证其原始授权消息',
    );
    assert(
      verifySig(crossB.publicKey, msgRound1, r1ev[crossB.publicKey].signature),
      '重启后第一轮 B 的证据不能验证其原始授权消息',
    );
    const r2 = d3.checkpoints.find((c) => c.digest === gen2Head3);
    const r2ev = Object.fromEntries(r2.evidence.map((e) => [e.publicKey, e]));
    assertEqual(r2ev[crossA.publicKey].signature, sigA2Cross);
    assertEqual(r2ev[crossC.publicKey].signature, sigC2Cross);
    assertEqual(
      d3.rotations.find((x) => x.rotationId === 'round-2-alt').status,
      'superseded',
      '重启后竞争候选拒绝结论丢失',
    );
  });

  await step('健康响应在重启后仍反映设备域状态', async () => {
    const health = (await api('GET', '/healthz')).json;
    const d1 = health.domains.find((d) => d.id === domainId);
    const d2 = health.domains.find((d) => d.id === domain2Id);
    const d3 = health.domains.find((d) => d.id === domain3Id);
    assert(d1 && d1.headDigest === rotationDigest, '健康响应中验收域链头不符');
    assert(d2 && d2.headDigest === domain2Head, '健康响应中并发域链头不符');
    assert(d3 && d3.headDigest === gen2Head3, '健康响应中跨代域链头不符');
  });

  await step('页面显示与接口相同的结果（链头、证据、检查点分组）', async () => {
    const page = await api('GET', '/');
    assertEqual(page.status, 200, '页面应可访问');
    assert(page.text.includes(rotationDigest), '页面未显示已激活链头摘要');
    assert(page.text.includes(memberA.publicKey), '页面未显示成员 A 的签名证据');
    assert(page.text.includes(memberB.publicKey), '页面未显示成员 B 的签名证据');
    assert(page.text.includes(sigA), '页面未显示成员 A 的签名值');
    assert(page.text.includes('rot-2026-001'), '页面未显示轮换标识');
    assert(page.text.includes('已激活'), '页面缺少已激活检查点分组');
    assert(page.text.includes('已拒'), '页面缺少已拒检查点分组');
    assert(page.text.includes('待签'), '页面缺少待签检查点分组');
    assert(page.text.includes('race-1') && page.text.includes('race-2'), '页面未显示竞争候选记录');
    assert(page.text.includes('round-1') && page.text.includes('round-2'), '页面未显示跨代轮换记录');
    assert(page.text.includes(sigA1Cross) && page.text.includes(sigB1Cross), '页面未保留第一轮两份历史证据');
    assert(page.text.includes(sigA2Cross) && page.text.includes(sigC2Cross), '页面未显示第二轮固化证据');
  });

  console.log('');
  if (failures > 0) {
    console.error(`验收失败：${failures} 项未通过`);
    process.exit(1);
  }
  console.log('验收全部通过。');
  process.exit(0);
}

main().catch((err) => {
  console.error(`验收执行异常：${err.stack || err}`);
  process.exit(1);
});
