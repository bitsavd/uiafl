# S7COMM 黑盒模糊测试说明

本文档只保留当前 S7COMM fuzz 实验需要的核心内容：相关文件作用、种子生成与筛选、LLM 指导、启动 fuzz、观察结果，以及如何复现和分析疑似漏洞。

## 实验目标

目标 PLC 不能插桩，因此测试思路是：

```text
构造/筛选高质量 S7COMM 种子
  -> AFLNet 发送变异后的协议消息到真实 PLC
  -> 解析 PLC 返回的 COTP/S7 状态码作为黑盒状态反馈
  -> 扩展 AFLNet inferred protocol state machine, IPSM
  -> 保存异常样本
  -> 用 oracle 多次重放并判断是否可能是漏洞
```

测试结果需要结合可重放异常行为进行判断，例如：

```text
TCP/102 服务无响应
连接失败或异常断开
S7 错误码异常
PLC 健康检查失败
PLC 诊断报警或进入异常状态
```

## 相关文件

```text
tutorials/s7/run_s7comm_fuzz.sh
  启动 S7COMM AFLNet fuzz 的主脚本，负责编译 harness、设置环境变量、启动 afl-fuzz。

tutorials/s7/build_s7_synthetic_seeds.sh
  调用合成种子脚本，构造并验证 S7COMM 会话种子。

tutorials/s7/rebuild_s7_seeds.sh
  从 pcap 或旧 raw 种子重建输入 corpus。

tutorials/s7/check_s7_findings.sh
  对 fuzz 产生的异常样本做健康检查和重放验证。

tutorials/s7/in/
  默认 fuzz 输入种子目录。

tutorials/s7/in_llm_selected/
  LLM 或启发式筛选后的输入种子目录。

tutorials/s7/in_deep_selected/
  根据公开 S7COMM 结构资料生成并经 PLC 探测筛选的深挖种子目录。

tutorials/s7/in_deep_llm_selected/
  从 in_deep_selected 中再按漏洞挖掘价值排序精选的主跑种子目录。

tutorials/s7/out/
  默认 fuzz 输出目录。

tutorials/s7/s7.dict
  AFL 字典，包含 TPKT、COTP、S7 function、area 等 token。

tutorials/s7/vuln_analysis/
  对 fuzz 结果中的候选样本做最小化、解码、重放和漏洞影响分析。

tools/s7_synthetic_seeds.py
  构造 S7COMM 读、写、边界地址、异常功能码等候选种子，并可连接 PLC 验证。

tools/extract_s7_seeds.py
  从 pcap 中按 TCP/102、TPKT/COTP/S7COMM 结构提取完整会话种子。

tools/s7_seed_quality.py
  对种子做协议结构和丰富度评分。

tools/s7_llm_guidance.py
  对种子排序、生成变异建议和 AFL dictionary。可接 DeepSeek，也可退化为启发式。

tools/s7_hourly_llm_supervisor.py
  每小时读取 AFLNet 输出、oracle/triage 反馈和候选样本，构建语义状态机并生成下一轮变异指导。

tools/s7_feedback_seeds.py
  根据最小化出的异常入口生成反馈种子，例如短 S7 PDU、错误后恢复探测、长度/计数字段边界。

tools/s7_deep_seed_builder.py
  根据公开 S7COMM 结构资料生成 TSAP、PDU 协商、Read/Write Var、长度错配、block/control 类深挖种子。

tools/s7_oracle.py
  PLC 健康检查和 testcase 重放验证工具。

tools/s7_case_decode.py
  将 raw testcase 解码成 TPKT/COTP/S7 字段，便于定位触发异常的协议字段。

tools/s7_case_minimize.py
  在保持指定异常行为的前提下最小化 testcase。

tools/s7_harness.c
  本地 AFL 覆盖反馈 harness。正常 fuzz 时它只解析输入，不直接连接 PLC。

aflnet.c
  S7COMM 请求切分与 PLC 响应状态码解析逻辑。

afl-fuzz.c
  AFLNet 状态机更新、状态引导选 seed、异常事件记录和网络发送逻辑。
```

## 种子准备

优先使用合成并实测可通信的种子，因为之前 pcap 提取质量不稳定。

```bash
S7_TARGET=192.168.0.13 S7_PORT=102 \
tutorials/s7/build_s7_synthetic_seeds.sh tutorials/s7/in
```

合成种子覆盖：

```text
COTP Connection Request
S7 Setup Communication
Read Var: M/I/Q/DB/timer/counter
Write Var: M/Q/DB 边界写
异常 area、缺失 DB、远地址
block/control-style 探测
未知 function code
```

如果要从 pcap 重建：

```bash
tutorials/s7/rebuild_s7_seeds.sh pcap_S7comm tutorials/s7/in
```

如果要按公开协议结构资料生成深挖种子：

```bash
python3 tools/s7_deep_seed_builder.py \
  --target 192.168.0.13 --port 102 \
  --timeout 1.2 \
  --max-selected 24

python3 tools/s7_llm_guidance.py \
  --input-dir tutorials/s7/in_deep_selected \
  --output tutorials/s7/deep_llm_guidance.json \
  --dict-out tutorials/s7/s7_deep.dict \
  --select-out tutorials/s7/in_deep_llm_selected \
  --top-n 16
```

深挖种子主要覆盖：

```text
TSAP connection type: PG / OP / basic
Setup Communication: PDU length、AMQ 边界
Read Var: item_count、area、DB number、offset、transport size、multi item
Write Var: data length / item bit length 错配
Block/control function: 0x1A-0x1F、0x28、0x29
TPKT/S7 declared length mismatch
```

如果已经完成一轮 fuzz 和最小化，可以生成反馈种子：

```bash
python3 tools/s7_feedback_seeds.py \
  --target 192.168.0.13 --port 102 \
  --out tutorials/s7/in_feedback \
  --candidate-out tutorials/s7/in_feedback_candidates \
  --report tutorials/s7/feedback_seed_probe.json \
  --replace
```

下一轮可优先使用精选后的反馈种子：

```bash
S7_IN_DIR=tutorials/s7/in_feedback_selected \
S7_OUT_DIR=tutorials/s7/out_feedback_24h \
S7_TARGET=192.168.0.13 S7_PORT=102 \
tutorials/s7/run_s7comm_fuzz.sh 24h fast
```

种子质量判断主要看：

```text
是否是完整 TPKT/COTP/S7COMM 会话
是否能完成 COTP 和 S7 Setup
是否包含不同 function code
是否覆盖读、写、异常地址、异常 area、控制类功能
是否过长或重复
```

## LLM 指导

`tools/s7_llm_guidance.py` 用于两件事：

```text
1. 按漏洞发现价值对种子排序，生成 tutorials/s7/in_llm_selected/
2. 生成 AFL dictionary，写入 tutorials/s7/s7.dict
```

如果不配置模型，脚本会自动使用内置启发式。启发式会优先选择包含写变量、异常 area、DB 边界、控制/块相关功能的种子。

```bash
python3 tools/s7_llm_guidance.py \
  --input-dir tutorials/s7/in \
  --output tutorials/s7/llm_guidance.json \
  --dict-out tutorials/s7/s7.dict \
  --select-out tutorials/s7/in_llm_selected \
  --top-n 16
```

接入 DeepSeek 时不要把 API key 写进代码，使用环境变量：

```bash
export DEEPSEEK_API_KEY='你的新API key'

DEEPSEEK_MODEL=deepseek-v4-flash \
python3 tools/s7_llm_guidance.py \
  --input-dir tutorials/s7/in \
  --output tutorials/s7/llm_guidance.json \
  --dict-out tutorials/s7/s7.dict \
  --select-out tutorials/s7/in_llm_selected \
  --top-n 16
```

可选模型：

```text
deepseek-v4-flash  速度优先
deepseek-v4-pro    推理质量优先
```

也可以通过 `S7_LLM_CMD` 接任意本地或远程模型命令。脚本会把 JSON prompt 从 stdin 传入，并要求 stdout 返回 JSON。

```bash
S7_LLM_CMD='your-llm-cli --json' \
python3 tools/s7_llm_guidance.py \
  --input-dir tutorials/s7/in \
  --select-out tutorials/s7/in_llm_selected
```

### 每小时状态机指导

长跑时可以另开一个终端，每小时分析一次当前 AFLNet 输出：

```bash
export DEEPSEEK_API_KEY='你的API key'

python3 tools/s7_hourly_llm_supervisor.py \
  --watch --interval 3600 \
  --out-dir tutorials/s7/out_deep_len_24h \
  --guidance-dir tutorials/s7/llm_hourly \
  --target 192.168.0.13 --port 102
```

如果不配置 `DEEPSEEK_API_KEY` 或 `S7_LLM_CMD`，脚本会使用内置启发式生成同样格式的指导文件。

每轮输出：

```text
tutorials/s7/llm_hourly/<时间戳>/prompt.json
tutorials/s7/llm_hourly/<时间戳>/guidance.json
tutorials/s7/llm_hourly/<时间戳>/triage/
```

`guidance.json` 中重点看：

```text
state_model       当前语义状态机
next_strategy     下一轮目标状态、变异热点、推荐字典 token
stop_or_continue  continue / enough_for_24h / needs_new_seed_family
```

## 启动模糊测试

推荐使用 LLM/启发式筛选后的种子：

```bash
S7_IN_DIR=tutorials/s7/in_llm_selected \
S7_TARGET=192.168.0.13 S7_PORT=102 \
tutorials/s7/run_s7comm_fuzz.sh 24h fast
```

当前更推荐的 S7COMM 深挖主跑命令：

```bash
S7_IN_DIR=tutorials/s7/in_deep_llm_selected \
S7_DICT=tutorials/s7/s7_deep.dict \
S7_OUT_DIR=tutorials/s7/out_s7comm_deep \
S7_TARGET=192.168.0.13 S7_PORT=102 \
tutorials/s7/run_s7comm_fuzz.sh 24h fast
```

直接使用默认种子：

```bash
S7_TARGET=192.168.0.13 S7_PORT=102 \
tutorials/s7/run_s7comm_fuzz.sh 24h fast
```

脚本参数格式：

```bash
tutorials/s7/run_s7comm_fuzz.sh <运行时长> <模式>
```

常用模式：

```text
fast      默认推荐，速度优先，适合长时间黑盒 fuzz
balanced 轻量 PLC 状态复位，用于对照状态残留
stable   更强复位，速度较慢，仅在 PLC 状态污染严重时使用
```

`none` 表示一直运行直到手动停止：

```bash
tutorials/s7/run_s7comm_fuzz.sh none fast
```

## 关键参数

`run_s7comm_fuzz.sh` 会启动类似命令：

```text
./afl-fuzz
  -i <输入目录>
  -o tutorials/s7/out
  -x tutorials/s7/s7.dict
  -N tcp://<PLC_IP>/102
  -P S7COMM
  -E
  -R
  -h 0
  -d
  -- ./tools/s7_harness @@
```

含义：

```text
-N      远程 PLC 地址
-P      选择 S7COMM 协议解析器
-E      启用 AFLNet 状态感知模式
-R      保存 replayable queue
-d      跳过确定性阶段，提高网络 fuzz 效率
-x      加载 S7 字典指导变异
```

S7 黑盒默认降噪参数：

```text
S7_STATE_COMPACT=1             压缩状态，减少无意义状态爆炸
S7_STATE_STRICT=1              只把明确 COTP/S7 语义计入状态
S7_STATE_BITMAP_FEEDBACK=0     不把远端响应直接混入 AFL bitmap
S7_SKIP_NET_CALIBRATION=1      校准阶段不打 PLC
S7_TRUST_LOCAL_CALIBRATION=1   信任本地 harness 校准稳定性
S7_MAX_TESTCASE=512            限制单个 testcase 长度，提高效率
```

这些设置不会关闭黑盒状态反馈。PLC 响应仍会被解析成 AFLNet 的 `state_sequence`，用于 IPSM、新状态路径和状态引导变异。

## 黑盒状态反馈原理

PLC 不能插桩，所以覆盖率不是真实 PLC 代码覆盖率。当前反馈由两部分组成：

```text
1. tools/s7_harness.c 的本地结构覆盖
2. aflnet.c 解析 PLC 返回包得到的黑盒协议状态
```

S7 状态提取位置：

```text
aflnet.c: extract_response_codes_s7comm()
```

提取字段：

```text
COTP packet class
S7 ROSCTR
S7 function code
S7 error class
S7 error code
Read Var item return code
```

这些字段会组合成状态 ID，再由 `afl-fuzz.c` 更新 IPSM：

```text
update_state_bitmap()
update_state_aware_variables()
choose_target_state()
choose_seed()
```

因此当前实验可以发现“协议响应状态变化”和“异常网络行为”，但不能声称拿到了 PLC 固件内部真实代码覆盖率。

## 查看运行结果

默认输出：

```text
tutorials/s7/out/fuzzer_stats
tutorials/s7/out/queue/
tutorials/s7/out/replayable-queue/
tutorials/s7/out/replayable-new-ipsm-paths/
tutorials/s7/out/s7_events/events.log
tutorials/s7/out/s7_events/cases/
tutorials/s7/out/ipsm.dot
```

查看 AFL 统计：

```bash
cat tutorials/s7/out/fuzzer_stats
```

查看 S7 异常事件类型：

```bash
awk '{for(i=1;i<=NF;i++) if($i ~ /^kind=/) print $i}' \
  tutorials/s7/out/s7_events/events.log | sort | uniq -c | sort -nr
```

常见事件：

```text
s7_item_abnormal            PLC 返回异常 item return code
recv_error_testcase         接收响应时连接错误或 socket 错误
no_response_testcase        整个 testcase 没有响应
no_response_after_message   某条消息之后响应未增长
```

生成状态机图片：

```bash
dot -Tpng tutorials/s7/out/ipsm.dot -o tutorials/s7/out/ipsm.png
```

## 漏洞筛选与复现

fuzz 结束或阶段性暂停后，先不要只看 AFL crash。真实 PLC 黑盒测试中，更重要的是异常样本能否稳定重放。

批量检查：

```bash
S7_TARGET=192.168.0.13 S7_PORT=102 \
tutorials/s7/check_s7_findings.sh tutorials/s7/out
```

单独健康检查：

```bash
./.venv/bin/python tools/s7_oracle.py \
  --target 192.168.0.13 --port 102 health
```

单个 testcase 重放：

```bash
./.venv/bin/python tools/s7_oracle.py \
  --target 192.168.0.13 --port 102 \
  replay tutorials/s7/out/s7_events/cases/<case.raw> \
  --repeats 5 --delay 0.2
```

优先分析的样本：

```text
重放多次都触发同类异常
触发后 health check 失败
触发 PLC 诊断报警
触发 TCP/102 长时间不可连接
触发 CPU STOP、通信模块异常或需要手动恢复
```

普通 S7 错误码本身不一定是漏洞。只有当异常可重放，并且影响 PLC 服务可用性、状态一致性或控制逻辑时，才进入漏洞复现分析。

## 推荐完整流程

```bash
# 1. 构造并验证种子
S7_TARGET=192.168.0.13 S7_PORT=102 \
tutorials/s7/build_s7_synthetic_seeds.sh tutorials/s7/in

# 2. LLM 或启发式筛选种子并生成字典
python3 tools/s7_llm_guidance.py \
  --input-dir tutorials/s7/in \
  --output tutorials/s7/llm_guidance.json \
  --dict-out tutorials/s7/s7.dict \
  --select-out tutorials/s7/in_llm_selected \
  --top-n 16

# 3. 启动 fuzz
S7_IN_DIR=tutorials/s7/in_llm_selected \
S7_TARGET=192.168.0.13 S7_PORT=102 \
tutorials/s7/run_s7comm_fuzz.sh 24h fast

# 4. 查看事件类型
awk '{for(i=1;i<=NF;i++) if($i ~ /^kind=/) print $i}' \
  tutorials/s7/out/s7_events/events.log | sort | uniq -c | sort -nr

# 5. 对异常样本做重放和健康检查
S7_TARGET=192.168.0.13 S7_PORT=102 \
tutorials/s7/check_s7_findings.sh tutorials/s7/out
```

阶段性保存结果时，只有在明确需要归档时再复制到 `tutorials/s7/fuzz_results/`。平时不要自动保存短跑结果，避免结果目录膨胀。
