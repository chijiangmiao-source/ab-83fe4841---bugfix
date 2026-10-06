'use strict';

/**
 * 持久化存储：单写者串行队列 + 原子文件提交。
 *
 * 每次 commit(mutator)：
 *  1. 在串行队列中执行 mutator（纯函数：state → {state, result}）；
 *  2. 若返回了新状态，则一次性写入临时文件、fsync、rename 替换、
 *     fsync 目录 —— 这是一次“持久化提交”，要么完整生效要么不生效；
 *  3. 只有落盘成功后才更新内存状态。
 *
 * 因此“收集到足够签名 → 激活候选 → 取代竞争候选 → 链头前进”
 * 永远落在同一次持久化提交里；并发的补签/重传在队列中串行收敛，
 * 不会产生第二个活动检查点。
 *
 * 启动加载时会校验已激活检查点的历史签名证据（见
 * rotation.repairCheckpointEvidence）：被历史版本缺陷改写的证据
 * 在同一启动流程中恢复为可验证的原始签名并原子落盘。
 */

const fs = require('node:fs');
const path = require('node:path');

const rotation = require('./rotation');

const STATE_VERSION = 1;

function initialState() {
  return { version: STATE_VERSION, domains: {} };
}

class Store {
  constructor(file) {
    this.file = file;
    this.state = null;
    this._queue = Promise.resolve();
  }

  /** 启动时加载；状态文件不存在则初始化空状态并落盘。 */
  load() {
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    if (fs.existsSync(this.file)) {
      const raw = fs.readFileSync(this.file, 'utf8');
      const parsed = JSON.parse(raw);
      if (!parsed || parsed.version !== STATE_VERSION || typeof parsed.domains !== 'object' || parsed.domains === null) {
        throw new Error(`状态文件损坏或版本不受支持：${this.file}`);
      }
      // 修复历史版本缺陷改写的已激活检查点证据；有修复则同次启动原子落盘。
      const repaired = rotation.repairCheckpointEvidence(parsed);
      if (repaired !== parsed) this._persist(repaired);
      this.state = repaired;
    } else {
      this.state = initialState();
      this._persist(this.state);
    }
    return this.state;
  }

  /**
   * 串行执行一次状态迁移。mutator 抛错时不产生任何持久化变更；
   * mutator 返回原状态引用时跳过落盘（纯拒绝路径不改变链头）。
   */
  commit(mutator) {
    const run = this._queue.then(() => {
      const outcome = mutator(this.state);
      if (!outcome || typeof outcome !== 'object' || !('state' in outcome)) {
        throw new Error('mutator 必须返回 { state, result }');
      }
      const { state, result } = outcome;
      if (state !== this.state) {
        this._persist(state);
        this.state = state;
      }
      return result;
    });
    // 队列本身不因单次失败而中断。
    this._queue = run.catch(() => {});
    return run;
  }

  /** 原子提交：写临时文件 → fsync → rename → fsync 目录。 */
  _persist(state) {
    const tmp = `${this.file}.tmp`;
    const fd = fs.openSync(tmp, 'w');
    try {
      fs.writeSync(fd, JSON.stringify(state, null, 2));
      fs.writeSync(fd, '\n');
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmp, this.file);
    const dirFd = fs.openSync(path.dirname(this.file), 'r');
    try {
      fs.fsyncSync(dirFd);
    } finally {
      fs.closeSync(dirFd);
    }
  }
}

module.exports = { Store, initialState, STATE_VERSION };
