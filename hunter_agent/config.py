# -*- coding: utf-8 -*-
"""Central configuration and safety limits."""
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional
import os


@dataclass
class HunterConfig:
    target: str = ""
    extra_scope: List[str] = field(default_factory=list)

    proxy: Optional[str] = "http://127.0.0.1:8080"
    delay: float = 0.4
    timeout: int = 10
    max_workers: int = 5
    verify_ssl: bool = False
    max_targets: int = 60

    max_iterations: int = 25
    autonomous: bool = True

    active_verification: bool = True
    max_verify_per_type: int = 10
    auto_verify_limit: int = 20

    llm_base_url: str = "https://api.moonshot.ai/v1"
    llm_api_key: str = ""
    llm_model: str = "kimi-k2-0711-preview"
    llm_temperature: float = 0.2
    llm_max_tokens: int = 2048

    report_dir: Path = Path("hunter_reports")

    @property
    def llm_enabled(self) -> bool:
        return bool(self.llm_api_key)

    @classmethod
    def from_env(cls, **overrides):
        cfg = cls(
            llm_base_url=os.getenv("HUNTER_LLM_BASE_URL", cls.llm_base_url),
            llm_api_key=os.getenv("HUNTER_LLM_API_KEY", "") or os.getenv("OPENAI_API_KEY", ""),
            llm_model=os.getenv("HUNTER_LLM_MODEL", cls.llm_model),
        )
        for key, value in overrides.items():
            if value is not None and hasattr(cfg, key):
                setattr(cfg, key, value)
        return cfg
