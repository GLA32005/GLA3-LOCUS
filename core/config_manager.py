"""
统一配置管理 — .locus/ 目录

配置层级（低覆盖高）：
  内置默认值 → .locus/config.yaml → 当前目录 .env → 命令行参数
"""

from __future__ import annotations

import copy
import os
import shutil
from pathlib import Path

import yaml

try:
    from dotenv import dotenv_values
except ImportError:
    def dotenv_values(path):
        """简易 .env 解析（无 python-dotenv 时的降级）"""
        result = {}
        p = Path(path)
        if not p.exists():
            return result
        for line in p.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                result[k.strip()] = v.strip().strip('"').strip("'")
        return result


# ── 内置默认值 ──────────────────────────────────────────────

DEFAULTS = {
    "llm": {
        "base_url": "http://127.0.0.1:8866",
        "api_key": "localkey",
        "model": "Qwen3.5-9B-MLX-8bit",
        "api_format": "",  # 自动推断
        "strong_base_url": "https://api.deepseek.com",
        "strong_api_key": "",
        "strong_model": "deepseek-v4-flash",
        "strong_budget": 20,
    },
    "storage": {
        "redis_url": "redis://localhost:6379",
        "neo4j_url": "bolt://localhost:7687",
        "neo4j_user": "neo4j",
        "neo4j_password": "password",
        "clickhouse_host": "localhost",
        "clickhouse_port": 9000,
        "clickhouse_db": "pentest",
    },
    "scan": {
        "risk_level": 3,
        "max_noise": 30,
        "max_think_rounds": 200,
        "max_runtime": 7200,
        "max_payload_retry": 3,
        "context_budget": 8000,
    },
    "api": {
        "host": "0.0.0.0",
        "port": 8086,
        "key": "changeme-to-a-strong-secret",
    },
}

# .env 变量名 → config key 映射
# 注意：全新架构下，已剥离 LLM_* 映射，大模型配置全权由 config.yaml 和 profile 接管
_ENV_MAP = {
    "REDIS_URL": "storage.redis_url",
    "NEO4J_URL": "storage.neo4j_url",
    "NEO4J_USER": "storage.neo4j_user",
    "NEO4J_PASSWORD": "storage.neo4j_password",
    "CLICKHOUSE_HOST": "storage.clickhouse_host",
    "CLICKHOUSE_PORT": "storage.clickhouse_port",
    "CLICKHOUSE_DB": "storage.clickhouse_db",
    "API_HOST": "api.host",
    "API_PORT": "api.port",
    "API_KEY": "api.key",
}


class ConfigManager:
    """统一配置管理，存储在 .locus/ 目录"""

    def __init__(self, project_dir: str = "."):
        self.project_dir = Path(project_dir).resolve()
        self.config_dir = self.project_dir / ".locus"
        self.config_file = self.config_dir / "config.yaml"
        self.profiles_dir = self.config_dir / "profiles"
        self._cache: dict | None = None

    # ── 目录管理 ─────────────────────────────────────────

    def ensure_dir(self):
        """创建 .locus/ 目录结构"""
        self.config_dir.mkdir(exist_ok=True)
        self.profiles_dir.mkdir(exist_ok=True)
        # 写入默认配置（如果不存在）
        if not self.config_file.exists():
            self._save_yaml(self.config_file, {})

    # ── 配置读取（合并层级）───────────────────────────────

    def get_all(self) -> dict:
        """返回完整合并配置"""
        if self._cache is not None:
            return self._cache
        merged = copy.deepcopy(DEFAULTS)
        # 层级 2：.locus/config.yaml
        if self.config_file.exists():
            user_cfg = self._load_yaml(self.config_file) or {}
            _deep_merge(merged, user_cfg)
        # 层级 3：.env 文件
        env_file = self.project_dir / ".env"
        dotenv_overrides = set()  # 记录 .env 已覆盖的 cfg_key
        if env_file.exists():
            env_vals = dotenv_values(str(env_file))
            for env_key, cfg_key in _ENV_MAP.items():
                if env_key in env_vals and env_vals[env_key]:
                    _set_nested(merged, cfg_key, _auto_type(env_vals[env_key]))
                    dotenv_overrides.add(cfg_key)
        # 层级 4：环境变量（运行时覆盖）
        # 但如果 .env 已经显式设置了某个 cfg_key，则跳过 shell 中的旧名
        for env_key, cfg_key in _ENV_MAP.items():
            if cfg_key in dotenv_overrides:
                continue  # .env 优先于 shell 残留
            val = os.environ.get(env_key)
            if val:
                _set_nested(merged, cfg_key, _auto_type(val))
        self._cache = merged
        return merged

    def get(self, key: str, default=None):
        """获取配置值，支持 dot notation: 'llm.model'"""
        cfg = self.get_all()
        return _get_nested(cfg, key, default)

    def set(self, key: str, value):
        """设置配置值并持久化到 .locus/config.yaml"""
        self.ensure_dir()
        user_cfg = self._load_yaml(self.config_file) or {}
        _set_nested(user_cfg, key, _auto_type(str(value)))
        self._save_yaml(self.config_file, user_cfg)
        self._cache = None  # 清缓存

    def show(self) -> str:
        """格式化输出当前配置（YAML）"""
        cfg = self.get_all()
        # 遮蔽敏感字段
        display = copy.deepcopy(cfg)
        for section in display.values():
            if isinstance(section, dict):
                for k, v in section.items():
                    if "key" in k.lower() and isinstance(v, str) and len(v) > 4:
                        section[k] = v[:4] + "****"
        return yaml.dump(display, allow_unicode=True, default_flow_style=False, sort_keys=False)

    # ── Profile 管理 ─────────────────────────────────────

    def save_profile(self, name: str):
        """保存当前配置为 profile"""
        self.ensure_dir()
        cfg = self.get_all()
        self._save_yaml(self.profiles_dir / f"{name}.yaml", cfg)

    def load_profile(self, name: str):
        """加载 profile 覆盖 config.yaml"""
        path = self.profiles_dir / f"{name}.yaml"
        if not path.exists():
            raise FileNotFoundError(f"Profile '{name}' 不存在")
        profile = self._load_yaml(path) or {}
        self._save_yaml(self.config_file, profile)
        self._cache = None

    def list_profiles(self) -> list[str]:
        """列出所有 profile"""
        if not self.profiles_dir.exists():
            return []
        return [p.stem for p in self.profiles_dir.glob("*.yaml")]

    # ── 导出为环境变量（供 main.py 使用）────────────────

    def export_to_env(self):
        """将配置导出为环境变量，供旧代码兼容使用。

        优先使用 .env 文件的值覆盖 shell 环境变量，
        因为 .env 是用户为该项目明确配置的，比 shell 全局 export 更可信。
        """
        # 先从 .env 文件直接读取，这些值应该覆盖 shell 环境变量
        env_file = self.project_dir / ".env"
        if env_file.exists():
            env_vals = dotenv_values(str(env_file))
            for env_key in _ENV_MAP:
                if env_key in env_vals and env_vals[env_key]:
                    os.environ[env_key] = env_vals[env_key]

        # 再用合并后的配置补充缺失的环境变量（不覆盖已有的）
        reverse_map = {v: k for k, v in _ENV_MAP.items()}
        cfg = self.get_all()
        for cfg_key, env_key in reverse_map.items():
            val = _get_nested(cfg, cfg_key)
            if val is not None and env_key not in os.environ:
                os.environ[env_key] = str(val)

        # 确保旧变量名也被设置（兼容 main.py 中的直接引用）
        llm_cfg = self.get_all().get("llm", {})
        if llm_cfg.get("base_url") and "ANTHROPIC_BASE_URL" not in os.environ:
            os.environ["ANTHROPIC_BASE_URL"] = str(llm_cfg["base_url"])
        if llm_cfg.get("api_key") and "ANTHROPIC_API_KEY" not in os.environ:
            os.environ["ANTHROPIC_API_KEY"] = str(llm_cfg["api_key"])

    # ── 内部方法 ─────────────────────────────────────────

    @staticmethod
    def _load_yaml(path: Path) -> dict | None:
        try:
            with open(path) as f:
                return yaml.safe_load(f)
        except Exception:
            return None

    @staticmethod
    def _save_yaml(path: Path, data: dict):
        with open(path, "w") as f:
            yaml.dump(data, f, allow_unicode=True, default_flow_style=False, sort_keys=False)


# ── 工具函数 ─────────────────────────────────────────────

def _deep_merge(base: dict, override: dict):
    """递归合并 override 到 base"""
    for k, v in override.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v


def _get_nested(d: dict, key: str, default=None):
    """dot notation 读取: 'llm.model'"""
    parts = key.split(".")
    cur = d
    for p in parts:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


def _set_nested(d: dict, key: str, value):
    """dot notation 写入: 'llm.model'"""
    parts = key.split(".")
    cur = d
    for p in parts[:-1]:
        if p not in cur or not isinstance(cur[p], dict):
            cur[p] = {}
        cur = cur[p]
    cur[parts[-1]] = value


def _auto_type(val: str):
    """自动类型转换：'8086' → 8086, 'true' → True"""
    if val.lower() in ("true", "false"):
        return val.lower() == "true"
    try:
        return int(val)
    except ValueError:
        pass
    try:
        return float(val)
    except ValueError:
        pass
    return val
