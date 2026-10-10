# 协议异常检测系统

协议异常检测系统是一个放在 AFLNet 根目录下使用的 Web 管理界面，用于协议检测任务创建、运行监控、异常样本分析、状态机展示、样本回放和报告生成。

将 `aflnet-ui` 目录复制到 AFLNet 根目录后即可使用，目录结构应类似：

```text
aflnet/
  afl-fuzz
  aflnet-replay
  tutorials/
  aflnet-ui/
```

## 功能

- 总览看板：查看运行任务、执行速度、路径数量、异常数量和最近任务。
- 检测任务：选择协议、新建任务、启动任务、停止任务、移除任务记录。
- 协议选择：支持工控协议和网络协议分类选择。
- 异常分析：查看趋势图、异常样本、回放结果和协议状态机。
- 报告中心：预览任务报告并导出 Markdown、PDF。
- 系统设置：配置默认运行时长、超时、并行任务、接入方式和结果策略。

## 目录

```text
aflnet-ui/
  README.md
  docs/
    PLAN.md
    系统流程说明.md
    截图/
  backend/
    app/
    data/
    requirements.txt
  frontend/
    src/
    package.json
    vite.config.js
  runs/
```

## 安装依赖

后端依赖：

```bash
cd aflnet-ui/backend
pip install -r requirements.txt
```

前端依赖：

```bash
cd aflnet-ui/frontend
npm install
```

系统需要安装 Graphviz 和 GCC 工具链，用于状态机渲染及源码行覆盖统计：

```bash
sudo apt-get install -y graphviz build-essential
```

从 AFLNet 根目录安装新增协议的本地参考服务：

```bash
make
bash aflnet-ui/targets/setup_targets.sh
```

安装脚本准备 FTP、DNS、DICOM、IPP、DTLS 1.2 的运行依赖和参考服务，使用仓库已有种子。需要 Python 3、Git、GCC 及 Ubuntu/Debian 的 apt 工具；构建产物保存在 `aflnet-ui/targets/.cache/`，换机器后重新运行脚本即可。IPP 服务还依赖系统 CUPS、Avahi 运行库，可用 `sudo apt-get install -y cups-ipp-utils` 安装。

## 协议与目标

已接入任务检测、状态分析、样本回放和报告的协议包括 MQTT、Modbus、RTSP、FTP、DNS、DICOM、IPP、DTLS 1.2。协议选择会自动填入本地参考服务的端口与启动等待时间。填写外部设备地址时，本机向该设备发包，不启动或终止远端服务；只在获得相应执行反馈时展示代码覆盖指标。

FTP、DNS、DICOM、IPP 的参考服务未做 AFL 插桩，采用协议响应反馈调度，不展示代码行覆盖率。参考服务用于本地验证流程，不代表真实设备的完整业务环境。FTP 登录凭据、打印机 URI、DICOM AE 与 DTLS 密钥等需与实际设备匹配；不是仅填写任意网址就能覆盖所有业务。各协议种子与验证记录见 `docs/协议接入与验证.md`。

## 启动

先启动后端：

```bash
cd aflnet-ui/backend
uvicorn app.main:app --host 0.0.0.0 --port 18080
```

再启动前端：

```bash
cd aflnet-ui/frontend
npm run dev -- --host 0.0.0.0 --port 5174
```

打开浏览器访问：

```text
http://127.0.0.1:5174
```

## 使用流程

1. 打开总览看板，确认后端服务正常。
2. 进入检测任务页面，点击“选择协议”。
3. 在工控协议或网络协议中选择检测协议。
4. 点击“新建任务”，填写目标地址、运行时长和检测策略。
5. 在任务列表中启动任务，查看任务状态和运行指标。
6. 进入异常分析页面，查看速度与覆盖趋势、异常样本和协议状态机。
7. 对异常样本点击“回放”，查看复现结果。
8. 进入报告中心，预览并导出 Markdown 或 PDF 报告。
9. 在系统设置中调整默认参数和策略。

## 结果数据

新建任务的结果默认保存在：

```text
aflnet-ui/runs/
```

任务索引和系统设置保存在：

```text
aflnet-ui/backend/data/
```

移除任务记录只会从系统列表中隐藏任务，不会删除已生成的结果数据。

项目自带 MQTT 6 小时初始样例，包含统计数据、趋势、状态机及异常回放样本，首次运行会自动加入任务列表。样例用于展示与分析，不包含恢复原检测进程所需的全部工作文件。实际检测任务的索引、结果和本地设置不纳入 Git，更新或上传项目不会上传这些任务数据。

代码行覆盖率按“已执行有效代码行 / 有效代码行总数”统计。本地源码目标通过独立的覆盖统计副本回放检测样本，使用 gcov 累计采集，不占用正在检测的目标端口。首次编译及采集需要一定时间；远程设备、未插桩目标或没有源码行统计的历史任务不显示该指标。行覆盖数据保存在各任务结果目录中，报告与图表使用同一份数据。

## 文档

```text
aflnet-ui/docs/PLAN.md
aflnet-ui/docs/系统流程说明.md
```
