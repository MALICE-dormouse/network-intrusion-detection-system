import json
import time
from typing import Optional

try:
    import requests
    _HTTP_OK = True
except ImportError:
    _HTTP_OK = False

OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "qwen2.5:3b"
_available_cache = {"checked": False, "available": False, "model": ""}


def is_available() -> bool:
    if not _HTTP_OK:
        return False
    if _available_cache["checked"]:
        return _available_cache["available"]
    try:
        resp = requests.get("http://localhost:11434/api/tags", timeout=3)
        if resp.status_code == 200:
            models = resp.json().get("models", [])
            _available_cache["available"] = len(models) > 0
            _available_cache["model"] = models[0]["name"] if models else ""
            _available_cache["checked"] = True
            return _available_cache["available"]
    except Exception:
        pass
    _available_cache["checked"] = True
    _available_cache["available"] = False
    return False


def _call_ollama(prompt: str) -> Optional[str]:
    if not _HTTP_OK or not is_available():
        return None
    model = _available_cache["model"] or DEFAULT_MODEL
    try:
        resp = requests.post(
            OLLAMA_URL,
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=30,
        )
        if resp.status_code == 200:
            return resp.json().get("response", "").strip()
    except Exception:
        pass
    return None


def analyze_alert(alert: dict) -> str:
    alert_type = alert.get("alert_type", "未知")
    source_ip = alert.get("source_ip", "未知")
    target = alert.get("target", "未知")
    score = alert.get("score", 0)
    level = alert.get("level", "低危")
    evidence = alert.get("evidence", "")

    prompt = f"""你是一名网络安全专家。请分析以下入侵检测告警并用中文给出简短的安全分析和建议（150字以内）。

告警类型: {alert_type}
来源IP: {source_ip}
目标: {target}
风险等级: {level} (分数: {score}/100)
检测依据: {evidence}

请按以下格式回复:
【攻击分析】{alert_type}的威胁程度和常见攻击目的
【处置建议】具体的防御措施（如阻断IP、限制端口等）
【后续观察】建议监控的重点"""

    result = _call_ollama(prompt)
    if result:
        return result

    suggestions = {
        "端口扫描": "攻击者正在探测目标主机开放的服务端口，属于侦察阶段。建议立即在防火墙中阻断来源IP的所有入站流量，并检查目标主机上非必要服务是否已关闭。",
        "暴力登录": f"攻击者通过反复尝试密码来猜测目标账号 {target} 的凭据。建议立即封锁来源IP {source_ip}，检查目标账号的登录日志，启用密码复杂度策略和账号锁定策略。",
        "异常访问频率": f"来源IP {source_ip} 的请求频率显著超出正常范围，可能在进行爬虫、暴力枚举或DoS准备。建议对该IP进行限速或临时封禁，分析其请求模式以确定攻击意图。",
        "可疑路径访问": f"检测到对敏感路径 {target} 的访问，可能是攻击者在探测Web应用漏洞。建议检查该路径是否存在安全风险，确认Web服务器配置已正确限制敏感目录访问。",
        "异常状态码": f"大量异常HTTP状态码表明请求被服务器拒绝或目标资源不存在，可能为目录暴力枚举或漏洞扫描。建议拦截持续产生404/403/500的IP，并审查访问日志。",
    }

    key = alert_type if alert_type in suggestions else "异常访问频率"
    return f"""【攻击分析】{key}的自动化分析（AI模型暂不可用，以下为专家规则建议）：
{suggestions.get(key, suggestions['异常访问频率'])}

【处置建议】在IPS中创建规则：DROP 来自 {source_ip} 的流量。
【后续观察】持续监控 {source_ip} 的后续行为，如发现新的攻击特征及时告警。"""


def suggest_defense(alert: dict) -> dict:
    alert_type = alert.get("alert_type", "未知")
    source_ip = alert.get("source_ip", "未知")
    target = alert.get("target", "未知")
    score = alert.get("score", 0)

    prompt = f"""你是一名网络安全自动化系统。根据以下告警，直接生成一个JSON格式的IPS防御规则。只返回JSON，不要任何解释。

告警: {alert_type} 来自 {source_ip}，目标 {target}，风险分 {score}

JSON格式:
{{"protocol": "any", "saddr": "{source_ip}", "dport": 0, "action": "drop", "priority": 100, "reason": "简短理由"}}

规则:"""

    result = _call_ollama(prompt)
    if result:
        try:
            return {"rule": json.loads(result.strip().lstrip("```json").rstrip("```").strip()), "ai_generated": True}
        except json.JSONDecodeError:
            pass

    priority = min(100, max(10, score + 20))
    return {
        "rule": {
            "protocol": "any",
            "saddr": source_ip if source_ip and source_ip != "未知" else "",
            "daddr": "",
            "sport": 0,
            "dport": 0,
            "action": "drop",
            "priority": priority,
            "enabled": True,
        },
        "ai_generated": False,
        "reason": f"基于{alert_type}告警自动生成的防御规则",
    }


def analyze_attack_chain(alerts: list) -> str:
    if not alerts:
        return "暂无足够告警数据用于攻击链分析。"

    alert_types = [a.get("alert_type", "未知") for a in alerts[:20]]
    sources = list(set(a.get("source_ip", "未知") for a in alerts[:20] if a.get("source_ip")))
    levels = [a.get("level", "") for a in alerts[:20]]
    critical_high = sum(1 for l in levels if l in ("高危", "critical", "high"))

    type_summary = "; ".join(alert_types[:5])
    source_summary = "; ".join(sources[:3])

    prompt = f"""你是一名网络安全事件响应专家。根据以下告警序列，分析可能的攻击链并用中文给出简短的攻击链条分析（200字以内）。

告警序列: {type_summary}
来源IP: {source_summary}
高危/严重告警数: {critical_high}/{len(alerts)}

请描述攻击者可能的攻击阶段（侦察→渗透→提权→横向移动→目标达成）和关键事件。"""

    result = _call_ollama(prompt)
    if result:
        return result

    has_portscan = any("端口扫描" in t for t in alert_types)
    has_brute = any("暴力登录" in t for t in alert_types)
    has_suspicious = any("可疑路径" in t for t in alert_types)
    has_highfreq = any("异常访问频率" in t for t in alert_types)
    has_status = any("异常状态码" in t for t in alert_types)

    stages = []
    if has_portscan:
        stages.append("🔍 侦察阶段: 攻击者对目标进行了端口扫描，探测开放服务")
    if has_brute:
        stages.append("🔑 渗透阶段: 攻击者对SSH/登录服务进行了暴力破解尝试")
    if has_suspicious:
        stages.append("🎯 利用阶段: 攻击者探测了敏感路径和漏洞入口")
    if has_highfreq:
        stages.append("⚡ 攻击实施: 大量异常请求表明攻击正在执行中")
    if has_status:
        stages.append("📊 结果反馈: 大量异常状态码表明攻击试探已获取了系统反馈")

    if not stages:
        stages.append("⚠ 告警类型分散，建议逐条审查以确定攻击模式")

    chain = """【攻击链推演】（AI模型暂不可用，基于规则统计推断）

""" + "\n".join(stages) + f"""

【关键发现】共检测到 {len(alerts)} 条告警，涉及 {len(sources)} 个可疑IP，其中 {critical_high} 条为高危/严重级别。
【建议措施】对已确认的攻击IP下发IPS阻断规则，加强目标主机的监控和日志审计。"""
    return chain
