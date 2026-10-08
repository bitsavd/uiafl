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
- 报告中心：预览任务报告并导出 Markdown。
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

系统需要安装 Graphviz，用于渲染协议状态机：

```bash
sudo apt-get install -y graphviz
```

## 启动

先启动后端：

```bash
cd aflnet-ui/backend
uvicorn app.main:app --host 0.0.0.0 --port 8000
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
8. 进入报告中心，预览并导出 Markdown 报告。
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

## 文档

```text
aflnet-ui/docs/PLAN.md
aflnet-ui/docs/系统流程说明.md
```
