# 常见网络攻击的检测与防御系统

本项目是《信息安全科技创新》课程的教学型安全实验项目，目标是围绕一个简单 Web 应用场景，完成常见网络攻击行为的检测、分析与展示，并为后续加入基础防御能力预留接口。当前实现以日志驱动的 IDS 为主，同时包含一个面向 Linux 内核模块的 IPS/防御联动接口层，便于课程展示从“检测”到“响应”的扩展方向。

## 项目定位

这个项目不是工业级商用 IDS/IPS，也不依赖实时抓包驱动、复杂分布式架构或重型机器学习模型。它更适合作为课程答辩和实验演示原型，强调以下几点：

- 能清楚展示常见网络攻击的行为特征。
- 能通过结构化日志进行误用检测和基础异常检测。
- 能输出可解释的告警结果、风险等级和统计信息。
- 能为后续加入 IPS 式主动响应提供接口和架构基础。

## 当前已实现功能

### 1. 日志导入与解析

系统支持加载内置示例日志，或上传 CSV 日志文件进行分析。当前 CSV 解析流程会提取以下字段：

- `timestamp`
- `source_ip`
- `target_ip`
- `port`
- `path`
- `status_code`
- `username`
- `login_success`

对应代码见 [src/parser/log_parser.py](C:/Users/tmp/Desktop/信安科技创新/network intrusion detection system/src/parser/log_parser.py) 和 [src/app.py](C:/Users/tmp/Desktop/信安科技创新/network intrusion detection system/src/app.py)。

### 2. IDS 检测能力

当前后端已经实现一组教学演示型检测规则，用于识别常见攻击或异常访问行为，包括：

- 端口扫描
- 暴力登录
- 可疑路径访问
- 异常状态码集中出现
- 异常访问频率

检测入口在 [src/detector/rules.py](C:/Users/tmp/Desktop/信安科技创新/network intrusion detection system/src/detector/rules.py)，示例测试覆盖见 [tests/test_detection.py](C:/Users/tmp/Desktop/信安科技创新/network intrusion detection system/tests/test_detection.py)。

### 3. 风险评分与告警分级

系统会根据检测结果为告警计算分数，并划分为 `低危`、`中危`、`高危` 三类风险等级，便于在答辩时说明系统如何从原始日志走到安全结论。

相关实现位于 [src/scoring/risk.py](C:/Users/tmp/Desktop/信安科技创新/network intrusion detection system/src/scoring/risk.py)。

### 4. Web 界面与分析接口

项目提供 Flask Web 服务，支持页面访问和 JSON API 调用。当前后端已提供：

- `GET /api/sample`：分析内置示例日志
- `POST /api/analyze`：上传 CSV 日志并分析
- `GET /api/alerts`：按条件筛选告警
- `GET /api/alerts/stats`：获取统计信息
- `GET /api/alerts/recent`：获取最近告警
- `GET /api/dashboard`：聚合 IDS 与防御模块状态

主应用入口见 [run.py](C:/Users/tmp/Desktop/信安科技创新/network intrusion detection system/run.py) 和 [src/app.py](C:/Users/tmp/Desktop/信安科技创新/network intrusion detection system/src/app.py)。

### 5. IPS / 防御扩展接口

仓库中已经包含一个防御接口层 [src/defense.py](C:/Users/tmp/Desktop/信安科技创新/network intrusion detection system/src/defense.py)，并在后端暴露了规则管理、状态查询和统计接口，例如：

- `GET /api/defense/status`
- `POST /api/defense/enable`
- `GET /api/defense/rules`
- `POST /api/defense/rules`
- `PUT /api/defense/rules/<id>`
- `DELETE /api/defense/rules/<id>`
- `GET /api/defense/stats`
- `PUT /api/defense/default-policy`

这部分当前主要用于教学型联动演示。在非 Linux 环境或没有对应内核设备时，会回退到模拟状态，不应理解为完整可部署的生产级防火墙系统。

## 适合课程汇报的系统设计表达

从课程项目角度，可以将本系统描述为三层：

1. **业务与数据产生层**
   一个简单 Web 站点或模拟业务服务，负责产生访问日志、登录日志和异常行为样本。

2. **安全检测与分析层**
   对日志进行解析、规则匹配、风险评分和统计汇总，形成 IDS 告警结果。

3. **结果展示与响应扩展层**
   通过 Web 页面和 API 展示分析结果，并预留防御规则管理与默认策略控制接口，支撑后续 IPS 扩展。

## 项目结构

```text
network intrusion detection system/
├── README.md
├── requirements.txt
├── pytest.ini
├── run.py
├── data/
│   └── sample_logs.csv
├── kernel_module/              # Linux 内核防御模块相关内容
├── frontend/                   # 前端工程与构建产物
├── src/
│   ├── app.py                  # Flask 应用与 API
│   ├── defense.py              # 防御接口封装
│   ├── detector/
│   │   └── rules.py            # IDS 检测规则
│   ├── parser/
│   │   └── log_parser.py       # CSV 日志解析
│   ├── scoring/
│   │   └── risk.py             # 风险评分
│   ├── static/                 # 传统模板前端资源
│   ├── templates/              # Flask 模板
│   └── utils/
│       └── serialization.py    # 序列化工具
└── tests/
    ├── conftest.py
    └── test_detection.py
```

## 运行环境

### 软件要求

- Python 3.10 及以上
- Flask
- flask-cors
- pytest

当前 Python 依赖见 [requirements.txt](C:/Users/tmp/Desktop/信安科技创新/network intrusion detection system/requirements.txt)。

### 硬件与系统建议

- Windows 10/11 或 Linux
- 至少 8 GB 内存
- 现代浏览器（Chrome / Edge）

说明：

- 纯 IDS 日志分析部分可以在 Windows 或 Linux 上运行。
- `src/defense.py` 对应的防御联动更偏向 Linux 环境；在其他环境下默认以模拟状态返回。

## 快速开始

安装依赖：

```bash
python -m pip install -r requirements.txt
```

启动后端：

```bash
python run.py
```

启动后访问浏览器中的本地 Flask 地址，加载示例数据或上传 CSV 文件即可查看检测结果。

## 测试

运行自动化测试：

```bash
python -m pytest
```

当前测试重点覆盖：

- 示例日志是否能触发预期告警类型
- 告警是否具备有效风险等级与分数
- 非法时间戳和非法端口是否会被接口拒绝

## CSV 输入格式

当前最小可用字段格式如下：

```text
timestamp,source_ip,target_ip,port,path,status_code,username,login_success
2026-07-08T10:00:00,192.168.1.20,10.0.0.5,80,/index,200,,
```

其中：

- `timestamp` 使用 ISO 风格时间字符串
- `port` 和 `status_code` 需要能转换为数字
- `login_success` 用于描述登录是否成功

## 当前仓库状态说明

当前仓库已经具备一个可以运行的基础版本，重点完成了：

- Flask 后端接口
- CSV 日志解析
- 基础 IDS 检测规则
- 风险评分
- 页面展示与统计接口
- 防御模块 API 壳层
- pytest 基础测试

同时，项目还保留了继续扩展为更完整课程原型的空间。

## 建议的后续完善方向

如果按课程答辩标准继续增强，下一步比较有价值的方向是：

- 增加误用检测特征库，把 SQL 注入、XSS、目录遍历等做成更清晰的签名检测。
- 增加异常检测模块，对访问频率、登录失败、敏感资源访问模式做更系统的统计判断。
- 增加攻击链关联，把同一源 IP 的扫描、注入、爆破等行为串成阶段化事件。
- 优化前端仪表盘，把告警分布、来源排行、攻击链结果和风险趋势展示得更完整。
- 增加更丰富的样例日志和测试用例，提高课程演示效果。
- 将 IDS 告警结果与 IPS 规则启停逻辑做更清晰的联动展示。

## 小组分工建议

如果按 4 到 5 人小组推进，比较合适的分工是：

- **总体设计与集成**：负责需求分析、总体架构、模块接口、进度协调和最终整合。
- **模拟业务网站与日志产生**：负责登录页面、普通页面、搜索接口和访问日志生成。
- **日志解析与数据预处理**：负责 CSV 字段标准化、数据清洗和事件抽取。
- **检测与评分**：负责规则设计、异常检测、风险评分和攻击链分析。
- **前端展示与测试文档**：负责可视化界面、演示脚本、测试验证和答辩材料整理。

## 安全与用途声明

本项目仅用于课程学习、教学演示和防御性安全研究。仓库中的检测规则、样例数据和防御接口用于帮助理解常见网络攻击检测与响应机制，不用于未授权攻击、渗透破坏或其他违规用途。