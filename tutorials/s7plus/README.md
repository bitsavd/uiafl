# S7CommPlus fuzz 工作区

这个目录只放 S7CommPlus 相关内容，和 `tutorials/s7` 里的经典 S7Comm 分开维护。

## 目录

```text
in_s7plus_final/
  当前建议用于主跑的 Plus 精选种子集，包含 HarpoS7 生成种子和 TIA pcap 提取种子。

s7plus_final.dict
  Plus 专用 AFL 字典。

out/
  默认 Plus fuzz 输出目录。

tutorials/s7plus/tools/s7plus_seed_builder.py
  从 HarpoS7 PoC 构造 Plus session/auth 入口候选种子。

tutorials/s7plus/tools/s7_tia_pcap_seeds.py
  从 TIA Portal pcap 提取 Plus 报文候选种子。

tutorials/s7plus/tools/s7plus_merge_corpus.py
  合并 HarpoS7/TIA 种子，按 PLC 响应和结构多样性精选最终 corpus。

build_s7plus_seeds.sh
  一键重新生成、探测、合并 Plus 种子。运行后会重建中间候选目录和 guidance 报告。

run_s7plus_fuzz.sh
  Plus 专用启动脚本。
```

## 状态反馈

当前 Plus 状态提取仍在 `aflnet.c` 的 `extract_response_codes_s7comm()` 中实现。Plus 分支识别 PLC 响应里的 `0x72` payload，并把前几个语义字段映射成 AFLNet 状态：

```text
0x72000000 | b1 << 16 | b2 << 8 | b3
```

这样 AFLNet 可以根据 PLC 返回的 S7CommPlus 响应差异扩展 IPSM。后续如果要进一步解耦，可以新增独立 `-P S7PLUS` 协议枚举，把请求切分、响应提取、状态机导出完全移到 Plus 专用实现。

## 重新生成种子

```bash
S7_TARGET=192.168.0.13 S7_PORT=102 \
tutorials/s7plus/build_s7plus_seeds.sh pcap_S7comm
```

流程：

```text
HarpoS7 PoC -> 构造 session/create-object 变体 -> PLC 探测
TIA pcap -> 提取真实 Plus 报文 -> 去重/截断/筛选
两路种子合并 -> 按响应、长度、prefix 多样性打分 -> in_s7plus_final
```

## 启动 fuzz

```bash
S7_TARGET=192.168.0.13 S7_PORT=102 \
tutorials/s7plus/run_s7plus_fuzz.sh 24h fast
```

等价于：

```bash
S7_IN_DIR=tutorials/s7plus/in_s7plus_final \
S7_DICT=tutorials/s7plus/s7plus_final.dict \
S7_OUT_DIR=tutorials/s7plus/out \
S7_TARGET=192.168.0.13 S7_PORT=102 \
tutorials/s7/run_s7comm_fuzz.sh 24h fast
```

## 观察进度

```bash
watch -n 10 'cat tutorials/s7plus/out/fuzzer_stats | egrep "run_time|last_path|execs_done|execs_per_sec|paths_total|paths_found|paths_favored|stability|unique_crashes|unique_hangs|slowest_exec_ms"'
```

```bash
tail -f tutorials/s7plus/out/s7_events/events.log
```

## 后续优化方向

```text
1. 把 aflnet.c 中的 Plus 状态提取拆成独立 S7PLUS 协议模块。
2. 在 tools/s7_harness.c 里增加更细的 0x72 本地解析覆盖反馈。
3. 根据 out/replayable-new-ipsm-paths 反推 Plus 状态机，生成下一轮定向种子。
4. 对 no_response / recv_error 样本做重放和最小化，区分正常拒绝、连接复位和疑似 PLC 异常。
```
