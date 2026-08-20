# -*- coding: utf-8 -*-
"""CLI for HUNTER v6."""
import argparse
import logging
from .config import HunterConfig
from .orchestrator import Orchestrator

BANNER = r"""
██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
        ⚡ AUTONOMOUS VERIFICATION AGENT v6.0 ⚡
        Developed by: Mamduh-911
"""


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="hunter",
        description="HUNTER v6 — Autonomous Security Verification Agent"
    )
    p.add_argument("-u", "--url")
    p.add_argument("--scope", nargs="*", default=[])
    p.add_argument("--no-verify", action="store_true")
    p.add_argument("--no-proxy", action="store_true")
    p.add_argument("--proxy")
    p.add_argument("--max-iter", type=int)
    p.add_argument("--model")
    p.add_argument("--delay", type=float)
    p.add_argument("--authorized", action="store_true")
    p.add_argument("--no-llm", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def confirm_authorization(target):
    print(f"\n⚠️ تأكيد التصريح: {target}")
    print("استخدم HUNTER فقط على أهداف لديك تصريح لاختبارها.")
    try:
        return input("هل لديك تصريح رسمي؟ [y/N]: ").strip().lower() == "y"
    except (EOFError, KeyboardInterrupt):
        return False


def main(argv=None):
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )
    print(BANNER)

    target = args.url or input("🎯 Target URL: ").strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    if not args.authorized and not confirm_authorization(target):
        print("❌ لم يتم تأكيد التصريح.")
        return 1

    cfg = HunterConfig.from_env()
    cfg.target = target
    cfg.extra_scope = args.scope
    cfg.proxy = None if args.no_proxy else (args.proxy or "http://127.0.0.1:8080")
    cfg.active_verification = not args.no_verify
    if args.no_llm:
        cfg.llm_api_key = ""
    if args.max_iter:
        cfg.max_iterations = args.max_iter
    if args.model:
        cfg.llm_model = args.model
    if args.delay is not None:
        cfg.delay = args.delay

    result = Orchestrator(cfg).run()
    print("\n" + "=" * 60)
    print(f"✅ HUNTER v6 انتهى | mode={result['mode']}")
    print(f"Findings: {result['findings']}")
    print(f"Confirmed: {result['confirmed']}")
    print(f"Likely: {result['likely']}")
    print(f"False Positive: {result['false_positive']}")
    for name, path in result["reports"].items():
        print(f"📄 {name}: {path}")
    return 0
