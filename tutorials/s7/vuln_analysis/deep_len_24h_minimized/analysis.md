# S7COMM 24h 结果最小化与下一轮优化

## 24h 结果筛选

输入目录：`tutorials/s7/out_deep_len_24h`

oracle/triage 输出：`tutorials/s7/vuln_analysis/triage_deep_len_24h`

结果统计：

```text
total candidates: 861
normal/noise: 688
s7_error_path_current_connection_reset: 172
transport_layer_current_connection_reset: 1
persistent_plc_fault: 0
unique AFL crashes/hangs: 0/0
PLC post-health: healthy
```

这说明 24h fuzz 没有发现 PLC 持久不可用或 AFL crash/hang。主要可复现现象集中在当前 TCP/COTP 连接被 PLC 主动关闭。

## 最小化样本

### event_001100_fn85_min.raw

文件：

```text
tutorials/s7/vuln_analysis/deep_len_24h_minimized/event_001100_fn85_min.raw
```

从 218 bytes 最小化到 62 bytes。10 次 replay 均可复现：

```text
cotp_cc
s7:rosctr=03:fn=f0:err=00/00
s7:rosctr=02:fn=85
connection reset by peer
post-health: healthy
```

结构：

```text
COTP Connection Request
S7 Setup Communication
COTP Data: short S7 PDU
COTP Data: short follow-up frame
```

判断：这是当前最有价值的异常入口。它不依赖截断 COTP Connection Request，而是走到 S7 层短 PDU 错误处理后关闭当前连接。还不是漏洞结论，因为 PLC 健康检查正常，但适合作为下一轮状态机构建和定向变异种子。

### event_000008_readvar_min.raw

文件：

```text
tutorials/s7/vuln_analysis/deep_len_24h_minimized/event_000008_readvar_min.raw
```

从 196 bytes 最小化到 85 bytes。10 次 replay 均可复现当前连接 reset，但 oracle 重新归类为低价值：

```text
cotp_cc
s7:rosctr=03:fn=f0:err=00/00
s7:rosctr=03:fn=04:err=00/00
connection reset by peer
post-health: healthy
tag: truncated_cotp_cr
```

结构：

```text
COTP Connection Request
S7 Setup Communication
valid ReadVar
truncated COTP Connection Request
```

判断：这是传输层噪声，不作为漏洞入口继续深挖。

## 反馈种子优化

新增脚本：

```text
tools/s7_feedback_seeds.py
```

它基于最小化结论生成三类种子：

```text
1. setup -> short/corrupt S7 PDU
2. setup -> short/corrupt S7 PDU -> valid read/setup probe
3. Read/Write/Block/Control 的 S7 长度、计数、错误恢复变体
```

已实际 probe PLC：

```text
candidates: tutorials/s7/in_feedback_candidates
kept: tutorials/s7/in_feedback
probe report: tutorials/s7/feedback_seed_probe.json
selected corpus: tutorials/s7/in_feedback_selected
selected raw seeds: 25
```

`tutorials/s7/in_feedback_selected` 按响应签名去重，保留了：

```text
fn=85 short S7 error path
fn=84 ReadVar item-count mismatch path
fn=81 block/control error path
normal ReadVar/WriteVar anchor seeds
error-recovery sequences
```

## Smoke fuzz

命令：

```bash
S7_IN_DIR=tutorials/s7/in_feedback_selected \
S7_OUT_DIR=tutorials/s7/out_feedback_smoke \
S7_TARGET=192.168.0.13 S7_PORT=102 \
AFL_TEE_LOG=1 \
tutorials/s7/run_s7comm_fuzz.sh 3m fast
```

结果：

```text
execs_done: 2004
execs_per_sec: 6.59
paths_total: 91
paths_found: 66
paths_favored: 12
max_depth: 2
stability: 100.00%
unique_crashes/hangs: 0/0
```

事件：

```text
recv_error_testcase: 33
s7_item_abnormal: 19
no_response_testcase: 5
no_response_after_message: 1
```

smoke triage：

```text
normal/noise: 22
high/s7_reset: 0
```

判断：短跑没有发现新漏洞候选，但新 corpus 可以正常启动，并且本地 harness map size 和初始路径丰富度明显高于最早的低质量种子。

## 下一轮推荐

推荐用反馈精选种子跑 24h：

```bash
S7_IN_DIR=tutorials/s7/in_feedback_selected \
S7_OUT_DIR=tutorials/s7/out_feedback_24h \
S7_TARGET=192.168.0.13 S7_PORT=102 \
AFL_TEE_LOG=1 \
tutorials/s7/run_s7comm_fuzz.sh 24h fast
```

另开终端，每小时生成一次 LLM/启发式状态机指导：

```bash
python3 tools/s7_hourly_llm_supervisor.py \
  --watch --interval 3600 \
  --out-dir tutorials/s7/out_feedback_24h \
  --guidance-dir tutorials/s7/llm_hourly_feedback \
  --target 192.168.0.13 --port 102 \
  --dict-out tutorials/s7/s7.dict \
  --select-out tutorials/s7/in_feedback_hourly_selected \
  --top-n 24
```

如果要接 DeepSeek：

```bash
export DEEPSEEK_API_KEY='你的新 API key'
export DEEPSEEK_MODEL=deepseek-v4-flash
```

下一轮重点观察：

```text
1. 是否出现 post-health 失败，即 PLC 在 replay 后无法正常 setup
2. 是否出现新的 s7_error_path_current_connection_reset，且不带 truncated_cotp_cr
3. 是否出现 fn=81/84/85 之后仍能继续产生更深层 S7 响应
4. 是否出现 PLC 诊断报警、CPU 状态变化、长时间 no_response
```
