#!/usr/bin/env python3
"""Find the cheapest three-AZ x86 enterprise ECS combinations for self-hosted K8S."""

from __future__ import annotations

import argparse
import json
import math
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any


HOURS_PER_MONTH = 730
SHAPES = {(4, 8): "control", (8, 16): "worker_standard", (8, 32): "worker_memory"}
SYSTEM_DISK_ARGS = [
    "--SystemDisk.Category", "cloud_essd",
    "--SystemDisk.PerformanceLevel", "PL0",
    "--SystemDisk.Size", "50",
]


def listify(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def run_aliyun(profile: str, product: str, action: str, parameters: list[str] | None = None,
               attempts: int = 3) -> dict[str, Any]:
    command = ["aliyun", product, action, "--profile", profile]
    if parameters:
        command.extend(parameters)
    last_error = ""
    for attempt in range(1, attempts + 1):
        proc = subprocess.run(command, capture_output=True, text=True, check=False)
        if proc.returncode == 0:
            try:
                return json.loads(proc.stdout)
            except json.JSONDecodeError as exc:
                last_error = f"invalid JSON: {exc}"
        else:
            last_error = proc.stderr.strip() or proc.stdout.strip()
        if attempt < attempts:
            time.sleep(attempt * 2)
    raise RuntimeError(f"aliyun {product} {action} failed: {last_error}")


def number(value: Any) -> float | None:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result if math.isfinite(result) else None


def fetch_instance_types(profile: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    next_token = ""
    while True:
        parameters = ["--MaxResults", "1600"]
        if next_token:
            parameters.extend(["--NextToken", next_token])
        response = run_aliyun(profile, "ecs", "DescribeInstanceTypes", parameters)
        result.extend(listify(response.get("InstanceTypes", {}).get("InstanceType")))
        next_token = str(response.get("NextToken", ""))
        if not next_token:
            return result


def is_candidate(item: dict[str, Any]) -> bool:
    shape = (int(item.get("CpuCoreCount", 0)), int(float(item.get("MemorySize", 0))))
    instance_type = str(item.get("InstanceTypeId", ""))
    category = str(item.get("InstanceCategory", ""))
    return (
        shape in SHAPES
        and item.get("CpuArchitecture") == "X86"
        and int(item.get("GPUAmount", 0)) == 0
        and not item.get("LocalStorageCategory")
        and item.get("InstanceFamilyLevel") == "EnterpriseLevel"
        and category in {"Compute-optimized", "General-purpose"}
        and not any(marker in instance_type for marker in ("poc-test", "essdnum", "nps", ".ebm", "ecs.sn"))
    )


def describe_price(profile: str, region: str, instance_type: str, mode: str) -> float:
    parameters = [
        "--RegionId", region,
        "--ResourceType", "instance",
        "--InstanceType", instance_type,
        *SYSTEM_DISK_ARGS,
        "--Amount", "1",
        "--InternetMaxBandwidthOut", "0",
        "--Platform", "Linux",
    ]
    if mode == "prepaid":
        parameters.extend(["--PriceUnit", "Year", "--Period", "1", "--SpotStrategy", "NoSpot"])
    elif mode == "postpaid":
        parameters.extend(["--PriceUnit", "Hour", "--Period", "1", "--SpotStrategy", "NoSpot"])
    else:
        parameters.extend([
            "--PriceUnit", "Hour", "--Period", "1",
            "--SpotStrategy", "SpotAsPriceGo", "--SpotDuration", "1",
        ])
    response = run_aliyun(profile, "ecs", "DescribePrice", parameters)
    value = number(response.get("PriceInfo", {}).get("Price", {}).get("TradePrice"))
    if value is None or value <= 0:
        raise RuntimeError(f"invalid price for {region} {instance_type} {mode}")
    return value


def cheapest_pair(control: list[dict[str, Any]], worker: list[dict[str, Any]]) -> dict[str, Any] | None:
    combinations = []
    for control_item in control:
        for worker_item in worker:
            common_zones = sorted(set(control_item["zones"]) & set(worker_item["zones"]))
            if len(common_zones) < 3:
                continue
            combinations.append({
                "control": control_item,
                "worker": worker_item,
                "zones": common_zones,
                "prepaid_1y_cny": round(3 * control_item["prepaid_1y_cny"] + 3 * worker_item["prepaid_1y_cny"], 2),
                "postpaid_730h_cny": round(
                    3 * control_item["postpaid_hour_cny"] * HOURS_PER_MONTH
                    + 3 * worker_item["postpaid_hour_cny"] * HOURS_PER_MONTH,
                    2,
                ),
            })
    return min(combinations, key=lambda item: item["prepaid_1y_cny"]) if combinations else None


def fmt_currency(value: float) -> str:
    return f"¥{value:,.2f}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", default="server-ops")
    parser.add_argument("--expected-account-id", default="<account-id>")
    parser.add_argument("--base-data", type=Path, default=Path("artifacts/aliyun-ecs-pricing/aliyun-ecs-price-data.json"))
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/aliyun-ecs-pricing"))
    args = parser.parse_args()

    identity = run_aliyun(args.profile, "sts", "GetCallerIdentity")
    account_id = str(identity.get("AccountId", ""))
    if account_id != args.expected_account_id:
        raise RuntimeError(f"profile account mismatch: expected {args.expected_account_id}, got {account_id or 'unknown'}")
    base = json.loads(args.base_data.read_text(encoding="utf-8"))
    metadata = {item["InstanceTypeId"]: item for item in fetch_instance_types(args.profile) if is_candidate(item)}
    print(f"eligible instance types: {len(metadata)}", file=sys.stderr, flush=True)

    regions: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for index, region_info in enumerate(base["regions"], start=1):
        region = region_info["region"]
        region_name = region_info["region_name"]
        prepaid_map = base["availability"][region]["prepaid"]
        shape_candidates: dict[str, list[dict[str, Any]]] = {name: [] for name in SHAPES.values()}
        available_types = [
            instance_type for instance_type, zones in prepaid_map.items()
            if instance_type in metadata and len(zones) >= 3
        ]
        print(
            f"[{index}/{len(base['regions'])}] {region}: pricing {len(available_types)} three-AZ candidates",
            file=sys.stderr,
            flush=True,
        )
        for instance_type in available_types:
            item = metadata[instance_type]
            shape = (int(item["CpuCoreCount"]), int(float(item["MemorySize"])))
            try:
                prepaid = describe_price(args.profile, region, instance_type, "prepaid")
                postpaid = describe_price(args.profile, region, instance_type, "postpaid")
            except RuntimeError as exc:
                errors.append({"region": region, "instance_type": instance_type, "error": str(exc)})
                continue
            shape_candidates[SHAPES[shape]].append({
                "instance_type": instance_type,
                "family": item.get("InstanceTypeFamily"),
                "category": item.get("InstanceCategory"),
                "zones": prepaid_map[instance_type],
                "prepaid_1y_cny": round(prepaid, 2),
                "postpaid_hour_cny": postpaid,
            })

        for candidates in shape_candidates.values():
            candidates.sort(key=lambda item: item["prepaid_1y_cny"])
        converged = None
        if shape_candidates["worker_standard"]:
            worker = shape_candidates["worker_standard"][0]
            converged = {
                "worker": worker,
                "zones": worker["zones"],
                "prepaid_1y_cny": round(3 * worker["prepaid_1y_cny"], 2),
                "postpaid_730h_cny": round(3 * worker["postpaid_hour_cny"] * HOURS_PER_MONTH, 2),
            }
        regions.append({
            "region": region,
            "region_name": region_name,
            "candidates": shape_candidates,
            "three_node_converged": converged,
            "six_node_standard": cheapest_pair(shape_candidates["control"], shape_candidates["worker_standard"]),
            "six_node_memory": cheapest_pair(shape_candidates["control"], shape_candidates["worker_memory"]),
        })

    topology_keys = ("three_node_converged", "six_node_standard", "six_node_memory")
    rankings = {
        key: sorted(
            [
                {
                    "region": item["region"],
                    "region_name": item["region_name"],
                    **item[key],
                }
                for item in regions if item[key]
            ],
            key=lambda item: item["prepaid_1y_cny"],
        )
        for key in topology_keys
    }

    fetched_at = datetime.now().astimezone().isoformat(timespec="seconds")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.output_dir / "aliyun-k8s-cost-optimized-data.json"
    report_path = args.output_dir / "aliyun-k8s-cost-optimized.md"
    json_path.write_text(json.dumps({
        "fetched_at": fetched_at,
        "profile": args.profile,
        "account_id": account_id,
        "method": "cheapest X86 EnterpriseLevel Compute-optimized/General-purpose instance with >=3 prepaid zones",
        "regions": regions,
        "rankings": rankings,
        "errors": errors,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    titles = {
        "three_node_converged": "三节点融合：3×8核16G",
        "six_node_standard": "六节点标准：3×4核8G + 3×8核16G",
        "six_node_memory": "六节点内存增强：3×4核8G + 3×8核32G",
    }
    lines = [
        "# 阿里云自建 K8S 三可用区成本优化结果",
        "",
        f"- 查询时间：{fetched_at}",
        "- 候选范围：x86、企业级、无GPU/无本地盘、计算型或通用型，每种规格至少三个包年可售可用区",
        "- 价格包含每节点50GB ESSD PL0系统盘，不含公网带宽、独立数据盘、CLB和备份",
        "- 低价选择允许同一拓扑内控制面与工作节点使用不同企业级规格族，并完整披露实例型号",
        "",
    ]
    for key in topology_keys:
        lines.extend([
            f"## {titles[key]}",
            "",
            "| 排名 | 地域 | 控制面型号 | 工作节点型号 | 共同可用区 | 包年1年 | 月均 | 按量730h/月 |",
            "|---:|---|---|---|---|---:|---:|---:|",
        ])
        for index, item in enumerate(rankings[key][:10], start=1):
            if key == "three_node_converged":
                control_type = "融合部署"
                worker_type = item["worker"]["instance_type"]
            else:
                control_type = item["control"]["instance_type"]
                worker_type = item["worker"]["instance_type"]
            lines.append(
                f"| {index} | {item['region_name']} `{item['region']}` | `{control_type}` | `{worker_type}` | "
                f"{', '.join(item['zones'][:3])} | {fmt_currency(item['prepaid_1y_cny'])} | "
                f"{fmt_currency(item['prepaid_1y_cny'] / 12)} | {fmt_currency(item['postpaid_730h_cny'])} |"
            )
        if not rankings[key]:
            lines.append("| — | 无满足条件地域 | — | — | — | — | — | — |")
        lines.append("")
    lines.extend([
        "## 边界",
        "",
        f"- 询价错误：{len(errors)} 条。",
        "- 价格最低不代表性能一致；最终型号仍需核对CPU代际、网络PPS、磁盘带宽和镜像兼容性。",
        "- 三可用区库存是查询时刻快照，采购前必须再次验库存。",
        "",
    ])
    report_path.write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({
        "report": str(report_path.resolve()),
        "json": str(json_path.resolve()),
        "eligible_types": len(metadata),
        "errors": len(errors),
        "ranking_counts": {key: len(value) for key, value in rankings.items()},
    }, ensure_ascii=False, indent=2))
    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
