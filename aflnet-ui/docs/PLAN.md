# 协议异常检测系统计划书

## 1. 建设目标

本系统面向网络协议实现的漏洞挖掘、异常检测与测试过程观测。产品层统一命名为“协议异常检测系统”，前端不暴露底层引擎名称；实现层以当前仓库的 AFLNet 原有能力为核心，通过后端适配层完成任务配置、运行控制、状态监控、状态机可视化、结果回放与报告归档。

第一版目标是先做成一个可运行的小系统：用户能在界面上选择协议、填写目标服务与测试参数、启动/停止检测任务，并查看执行速度、路径数量、覆盖率、崩溃/超时、状态机变化和测试结果。当前优先把 MQTT、RTSP 做成完整闭环模板，其他协议先保留协议入口和模板结构，后续根据目标程序、种子、字典和真实设备接入情况逐步补齐。

## 2. 范围边界

### 2.1 本期包含

- AFLNet 原生命令包装：`afl-fuzz`、`aflnet-replay`、`afl-plot`、状态机 `ipsm.dot`。
- AFLNet 状态反馈能力：`-E` 状态感知、`-R` 区域级变异、`-q/-s` 状态与种子选择策略。
- 网络协议信息配置：`-N tcp://host/port` 或后续扩展 UDP/DTLS 场景。
- 输入种子、字典、目标程序、清理脚本、运行时长、超时、内存限制等基础参数配置。
- 结果文件解析：`fuzzer_stats`、`plot_data`、`ipsm.dot`、`replayable-crashes`、`replayable-hangs`、`replayable-queue`。
- 状态机、测试速度、覆盖率、路径增长、崩溃/超时等可视化。
- 参考现有前端风格：左侧菜单栏、顶部状态栏、主内容区、指标卡片、表格、图表和详情页。

### 2.2 本期明确不包含

- 不加入额外专用协议扩展、专用种子生成、专用检测规则或独立菜单入口。
- 不加入大模型、知识图谱、自动语义种子生成、AI 分析、AI 聚类等能力。
- 不修改 AFLNet 核心 fuzzing 算法，只做任务编排、输出解析和可视化包装。
- 不把 MQTT Formal Analysis 中的大模型/形式化分析流水线纳入第一版系统，只参考其中已有的 AFLNet 监控页面和图表展示方式。
- 前端界面不出现 AFLNet、afl-fuzz、aflnet-replay、本机绝对路径等底层实现细节；这些信息只保留在后端日志、内部配置或开发文档中。
- 前端不直接展示本机文件地址、输出目录和启动命令，避免把本地实验环境假设带到真实网口、远程目标或生产化部署场景。
- 界面不把协议成熟度直接暴露给最终用户；通过模板、目标接入方式和观测能力降级来承接不同协议与不同目标环境。

## 3. AFLNet 可包装能力整理

当前 AFLNet 支持的通用协议解析入口可作为协议下拉选项的基础，包括：

- 工控/物联网协议：MQTT、DICOM、IPP、SNMP、NTP、SNTP、DHCP、TFTP。
- 常见网络协议：RTSP、FTP、DNS、SMTP、SSH、TLS、DTLS12、SIP、HTTP。
- 其他协议扩展：保留协议插件式配置入口，后续新增协议时只需新增协议元数据和响应码解析适配。

## 4. 系统信息架构

左侧一级菜单应是并列、边界清晰的功能域，而不是把协议类别、过程步骤和结果资产混在同一层。协议类别放在“检测任务”的二级弹窗或抽屉中选择，不作为一级菜单直接罗列。

### 4.1 菜单结构

- 总览看板
  - 系统态势、运行中任务、关键指标、异常摘要。
- 检测任务
  - 新建任务、协议选择、目标配置、运行控制、任务列表和任务详情。
  - 协议选择使用二级弹窗：先选“工控协议 / 网络协议”，再选具体协议。
  - 工控协议第一版放通用工业/物联网协议能力，如 MQTT、DICOM、IPP、SNMP、NTP/SNTP、DHCP、TFTP。
  - 网络协议包括 RTSP、FTP、DNS、SMTP、SSH、TLS、DTLS12、SIP、HTTP。
  - 参数表单需要显示取值范围、单位和解释：状态/样本选择策略取值 1-3，运行时长使用 s/m/h，启动等待单位为微秒，单次执行超时单位为毫秒。
  - 支持“移除任务记录”：只从系统任务列表隐藏记录，不删除原始测试数据；后续通过历史数据导入重新加入。
- 异常分析
  - 覆盖率与速度趋势、状态机展示、状态转移列表、异常样本、样本回放合并在同一分析域内。
  - 后续状态转移得分、状态路径价值评估也放在此菜单下。
- 报告中心
  - 任务摘要、运行参数、指标截图、状态机图、异常样本和复现结论。
- 系统设置
  - 协议模板、执行环境、网口/端口策略、并发限制、外部工具路径等内部配置。

### 4.2 页面布局

第一版沿用 `task/alertmind` 的后台系统风格：左侧固定菜单、顶部标题与服务状态、主区域显示指标卡和工作面板。整体应更偏测试平台/实验平台，避免营销式页面。

核心页面：

- 总览页：最近任务、运行中任务、全局指标、异常摘要。
- 检测任务页：任务列表、创建任务入口、协议二级选择弹窗、目标与运行参数表单。
- 任务详情页：运行状态、指标曲线、状态机、异常样本摘要；不展示本机绝对路径和底层命令。
- 异常分析页：状态机 SVG/PNG 预览、速度/覆盖率趋势、崩溃/超时样本、回放结果。
- 报告页：面向交付的任务摘要、趋势图、状态机图、异常复核结论。

## 5. 推荐技术架构

### 5.1 前端

建议使用现有参考项目一致的 Vue 3 + Vite + Element Plus：

- Vue Router 管理页面。
- Element Plus 提供菜单、表格、表单、抽屉、上传、标签和消息提示。
- ECharts 或轻量 Canvas 图表展示 `plot_data`。
- Graphviz 渲染优先由后端生成 SVG/PNG，前端负责展示与刷新。
- 指标展示需要支持降级状态：未插桩、远程目标、非标准运行方式或权限不足时，覆盖率、状态机、路径等数据可能缺失，前端统一显示“未采集”“未生成”或“当前环境不可用”。

前端目录放在仓库新增路径：

```text
aflnet-ui/frontend/
```

### 5.2 后端

建议使用 Python FastAPI 做 AFLNet 包装层：

- 负责启动、停止、查询 fuzzing 进程。
- 负责解析 `fuzzer_stats`、`plot_data`、`ipsm.dot`。
- 负责调用 Graphviz 将 `ipsm.dot` 转为 SVG/PNG。
- 负责执行 `aflnet-replay` 并保存回放日志。
- 负责维护任务元数据与结果目录索引。

后端目录放在：

```text
aflnet-ui/backend/
```

第一版可以先使用本地 JSON/SQLite 存储任务元数据，避免过早引入复杂数据库。

### 5.3 运行目录

建议把每次测试任务隔离到独立目录：

```text
runs/
  20260819_153000_mqtt_mosquitto/
    task.json
    afl_stdout.log
    afl_stderr.log
    fuzzer_stats
    plot_data
    ipsm.dot
    ipsm.svg
    replayable-crashes/
    replayable-hangs/
    replayable-queue/
```

外部已有实验目录，例如 `/home/cym/桌面/datadisk/Industrial_Protocol_Fuzzing/mqtt/fuzz_runs/`，可以作为“导入历史任务”的数据源，而不是第一版默认运行目录。

默认历史样例优先使用 MQTT 原始种子运行记录 `20260730_090800_mqtt_builtin_seeds_6h/out`，该记录来自 `tutorials/mosquitto/in-mqtt` 种子，包含可展示的崩溃和超时样本。

### 5.4 真实环境适配

真实网络测试与本机实验环境不同，需要预留以下能力：

- 目标可能在远程主机、指定网口、隔离网络或容器网络中运行。
- 部分目标无法插桩，覆盖率、路径、状态机等指标可能不存在。
- 部分任务只做黑盒网络异常检测，只能采集连接错误、超时、响应码、崩溃代理信号或外部监控事件。
- 前端只展示业务化配置项，例如协议、目标地址、端口、网口、运行时长、策略模板；本地路径、底层命令和工具参数由后端模板管理。
- 数据模型中需要区分 `metric_status`：`available`、`partial`、`unavailable`，避免把缺失数据误当成 0。

### 5.5 协议模板与真实设备接口预留

协议检测不是只靠一个 URL 就能获得完整结果。完整检测需要协议模板、初始种子、目标启动方式和观测能力；真实设备或远程服务接入时，系统需要允许部分指标不可用，并把结果解释为外部观测。

第一版预留以下接口：

- 协议模板：协议名、传输层、默认端口、状态解析、请求切分、默认策略。
- 目标接入：标准检测、外部目标、后续容器/网口/设备代理。
- 种子来源：内置种子、上传种子、历史导入、后续流量提取。
- 观测能力：执行反馈、状态反馈、异常样本、回放结果按可用情况展示。
- 报告输出：从任务摘要、趋势指标、状态机、异常样本自动生成 Markdown 报告。

## 6. 数据模型草案

### 6.1 Task

```json
{
  "id": "20260819_153000_mqtt_mosquitto",
  "name": "MQTT Mosquitto 1h",
  "category": "industrial",
  "protocol": "MQTT",
  "netinfo": "tcp://127.0.0.1/18885",
  "input_dir": "tutorials/mosquitto/in-mqtt",
  "output_dir": "runs/20260819_153000_mqtt_mosquitto",
  "dictionary": "",
  "target_command": "mosquitto/src/mosquitto -p 18885",
  "cleanup_script": "",
  "duration": "1h",
  "aflnet_options": {
    "state_aware": true,
    "region_mutation": true,
    "false_negative_reduction": false,
    "state_selection": 3,
    "seed_selection": 3,
    "startup_delay_us": 20000,
    "timeout": "2000+",
    "memory_limit": "none"
  },
  "status": "running",
  "created_at": "2026-08-19T15:30:00+08:00"
}
```

### 6.2 Runtime Metrics

从 `fuzzer_stats` 读取：

- `execs_done`
- `execs_per_sec`
- `paths_total`
- `paths_found`
- `pending_total`
- `pending_favs`
- `bitmap_cvg`
- `unique_crashes`
- `unique_hangs`
- `last_path`
- `last_crash`
- `last_hang`
- `stability`
- `command_line`，仅内部保存，不在前端展示。

从 `plot_data` 读取：

- 时间序列。
- 路径总数增长。
- 执行速度变化。
- 覆盖率变化。
- 状态机节点数 `n_nodes`。
- 状态机边数 `n_edges`。

从 `ipsm.dot` 读取：

- 状态节点。
- 状态转移边。
- 边标签/响应码。
- 后续扩展：边出现次数、增量贡献、状态转移得分。

## 7. 第一版功能清单

### 7.1 基础可用版

- 系统骨架：前端菜单、顶部状态、路由页面。
- 任务配置表单：协议、目标地址、端口、运行模板、运行时长、策略选项。
- 第一批完整模板：MQTT、RTSP。
- 协议选择弹窗：一级选择工控协议/网络协议，二级选择具体协议。
- 参数说明：对有限取值和时间类配置显示单位、范围和含义，避免只显示裸数字。
- 任务运行控制：启动、停止、查看状态。
- 任务记录管理：支持移除记录但保留底层历史数据。
- 报告中心：选择任务、预览报告、导出 Markdown。
- 系统设置：展示运行策略、目标接入方式、数据管理策略和真实设备扩展项。
- 实时指标面板：运行时长、执行次数、执行速度、路径总数、覆盖率、崩溃、超时；缺失数据展示未采集。
- 曲线图：从 `plot_data` 展示路径增长、执行速度、覆盖率、状态机节点/边增长。
- 状态机展示：`ipsm.dot` 生成 `ipsm.svg`，前端定时刷新。
- 结果列表：崩溃、超时、队列样本、状态新路径样本。
- 基础回放：选择 crash/hang 样本，后端调用回放工具并展示结果。
- 前端隐藏本机绝对路径、输出目录、底层命令行。

### 7.2 第一版暂缓

- 多机并行 fuzzing 管理。
- 复杂权限、多用户、审计。
- 源码级覆盖率 gcov/lcov 自动化。
- 自动漏洞判定与根因定位。
- 自动生成协议种子。
- 大模型分析。

## 8. 后续扩展路线

### 阶段一：底层包装与可视化

交付一个本机可用的最小系统：

- 能跑任务。
- 能看 `fuzzer_stats` 和 `plot_data`。
- 能展示 `ipsm.dot`。
- 能看到 crash/hang 列表。
- 能回放单个样本。

### 阶段二：任务管理与实验对比

- 任务复制与参数模板。
- 历史任务导入。
- 多任务指标对比。
- 不同 `-q/-s` 策略、字典、种子集的实验对比。
- 任务报告导出。

### 阶段三：状态机分析增强

- 状态转移表格。
- 状态节点/边新增时间。
- 状态转移覆盖率。
- 状态转移得分。
- 高价值状态路径标记。

状态转移得分可以先按简单公式实现：

```text
score(edge) =
  new_path_weight * 新增路径贡献
  + rarity_weight * 稀有状态权重
  + crash_weight * 是否关联 crash/hang
  + recency_weight * 最近新增程度
```

第一版只预留数据结构和页面入口，等基础流程稳定后再实现。

### 阶段四：复现、最小化与报告

- crash/hang 自动回放队列。
- 回放成功/失败状态标记。
- `afl-tmin` 或自定义流程做样本最小化。
- ASAN/GDB 日志附件管理。
- 报告模板：任务参数、趋势图、状态机、异常样本、复现结论。

## 9. 参考资料与可复用内容

### 9.1 当前仓库

- `README.md`：AFLNet 使用说明、参数说明、crash/hang 回放流程。
- `docs/status_screen.txt`：AFL 状态指标解释，可用于页面指标说明。
- `aflnet.c`、`aflnet.h`：协议响应码解析入口和协议支持清单。
- `tutorials/mosquitto/`：MQTT 示例，可作为第一版联调目标之一。
- `tutorials/live555/`、`tutorials/lightftp/`、`tutorials/dnsmasq/`：RTSP、FTP、DNS 示例。

### 9.2 桌面 task 参考

- `/home/cym/桌面/task/alertmind/frontend/src/App.vue`：左侧菜单、顶部状态、主内容区结构。
- `/home/cym/桌面/task/alertmind/frontend/src/styles.css`：后台系统风格、指标卡片、面板、表格布局。
- `/home/cym/桌面/task/交付材料/演示截图/`：可参考整体视觉层次和页面组织。

注意：AlertMind 里有大模型设置和 AI 聚类内容，本项目不复用这些功能，只参考界面结构和样式组织。

### 9.3 datadisk 参考

- `/home/cym/桌面/datadisk/Industrial_Protocol_Fuzzing/mqtt/fuzz_runs/*/fuzzer_stats`
- `/home/cym/桌面/datadisk/Industrial_Protocol_Fuzzing/mqtt/fuzz_runs/*/plot_data`
- `/home/cym/桌面/datadisk/Industrial_Protocol_Fuzzing/mqtt/fuzz_runs/*/ipsm.dot`
- `/home/cym/桌面/datadisk/Industrial_Protocol_Fuzzing/mqtt/results/*_monitor/index.html`

这些文件可以作为第一版前后端解析和可视化的样例数据。

## 10. 第一版验收标准

- 可以从界面新建一个 MQTT 或 RTSP 测试任务，并由后端生成正确的底层执行命令。
- 可以启动任务，后端能记录进程 PID、输出目录和运行日志。
- 可以停止任务，停止后任务状态正确变更。
- 页面能读取并刷新 `fuzzer_stats`。
- 页面能绘制 `plot_data` 中的路径、速度、覆盖率、状态机节点/边曲线。
- 页面能展示由 `ipsm.dot` 渲染出的状态机图。
- 页面能列出 `replayable-crashes` 和 `replayable-hangs`。
- 可以选择一个样本调用后端回放接口，并保存/展示回放输出。
- 页面和菜单中不出现大模型、AI、知识图谱等入口。
- 前端页面中不出现 AFLNet、afl-fuzz、aflnet-replay、本机绝对路径、输出目录或底层启动命令。
- 未插桩或缺少结果文件时，页面能以“未采集/未生成”降级展示，不报错、不误显示为 0。

## 11. 实施建议

建议先从“读历史结果并展示”做起，再接入“启动真实任务”。这样可以快速把 UI、数据解析、图表和状态机展示跑通，避免第一步就卡在目标程序编译、端口占用或 fuzzing 运行时间上。

推荐顺序：

1. 搭建前端页面骨架和后端 API 骨架。
2. 用 datadisk 里的 MQTT 历史 `fuzzer_stats`、`plot_data`、`ipsm.dot` 做只读展示。
3. 接入 Graphviz 渲染状态机。
4. 接入 AFLNet 任务启动/停止。
5. 接入 crash/hang 列表和 `aflnet-replay`。
6. 再做任务模板、实验对比、状态转移得分和报告导出。
