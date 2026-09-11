#!/usr/bin/env python3
"""
AcornFox Desktop Preflight (AFD-01)
Strictly read-only inspection script.

Outputs structured JSON (and optional Chinese summary mode).
Rules:
- Read-only environment inspection only.
- installation_status is always "not_checked".
- No hardware_eligible or runtime_ready over-inferencing.
- Disk usage free bytes for target path or None.
- All probe failures explicitly reported as None/null with status.
"""

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys


def get_cpu_cores():
    cores = os.cpu_count()
    return cores if cores and cores > 0 else None


def get_memory_info(system):
    """
    Returns (total_ram_mb, available_ram_mb, memory_probe_status, is_estimated)
    """
    total_mb = None
    available_mb = None
    probe_status = "unavailable"
    is_estimated = False

    if system == "Darwin":
        try:
            out = subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True, timeout=3).strip()
            total_mb = int(out) // (1024 * 1024)
            probe_status = "ok"
        except Exception:
            pass

        try:
            vm_out = subprocess.check_output(["vm_stat"], text=True, timeout=3)
            # Mac page size parsing using regex
            m = re.search(r"page size of (\d+) bytes", vm_out)
            if m:
                page_size = int(m.group(1))
                free_pages = 0
                inactive_pages = 0
                for line in vm_out.splitlines():
                    if line.startswith("Pages free:"):
                        free_pages = int(line.split(":")[1].strip().rstrip("."))
                    elif line.startswith("Pages inactive:"):
                        inactive_pages = int(line.split(":")[1].strip().rstrip("."))
                available_mb = (free_pages + inactive_pages) * page_size // (1024 * 1024)
                is_estimated = True
            else:
                available_mb = None
        except Exception:
            available_mb = None

    elif system == "Linux":
        try:
            if os.path.exists("/proc/meminfo"):
                with open("/proc/meminfo", "r", encoding="utf-8") as f:
                    for line in f:
                        if line.startswith("MemTotal:"):
                            total_mb = int(line.split()[1]) // 1024
                        elif line.startswith("MemAvailable:"):
                            available_mb = int(line.split()[1]) // 1024
                if total_mb is not None:
                    probe_status = "ok"
        except Exception:
            pass

    elif system == "Windows":
        probe_status = "unsupported_in_script"

    return total_mb, available_mb, probe_status, is_estimated


def check_virtualization(system):
    """
    Returns (cpu_virt_flag, dev_kvm_accessible, virt_type, probe_status)
    CPU virtualization flag and /dev/kvm presence/accessibility are observed separately.
    """
    cpu_virt_flag = False
    dev_kvm_accessible = False
    virt_type = "none"
    probe_status = "unavailable"

    if system == "Darwin":
        try:
            hv = subprocess.check_output(["sysctl", "-n", "kern.hv_support"], text=True, timeout=3).strip()
            cpu_virt_flag = (hv == "1")
            virt_type = "apple_hypervisor" if cpu_virt_flag else "none"
            probe_status = "ok"
        except Exception:
            virt_type = "unknown"
            probe_status = "failed"

    elif system == "Linux":
        try:
            if os.path.exists("/proc/cpuinfo"):
                with open("/proc/cpuinfo", "r", encoding="utf-8") as f:
                    cpuinfo = f.read()
                cpu_virt_flag = ("vmx" in cpuinfo or "svm" in cpuinfo)

            # Check /dev/kvm separately
            if os.path.exists("/dev/kvm"):
                dev_kvm_accessible = os.access("/dev/kvm", os.R_OK | os.W_OK)

            if cpu_virt_flag:
                if os.path.exists("/sys/module/kvm_amd/parameters/nested"):
                    try:
                        with open("/sys/module/kvm_amd/parameters/nested", "r", encoding="utf-8") as f:
                            if f.read().strip() == "1":
                                virt_type = "kvm_amd_nested"
                    except Exception:
                        pass
                elif os.path.exists("/sys/module/kvm_intel/parameters/nested"):
                    try:
                        with open("/sys/module/kvm_intel/parameters/nested", "r", encoding="utf-8") as f:
                            if f.read().strip().lower() in ("1", "y"):
                                virt_type = "kvm_intel_nested"
                    except Exception:
                        pass
                elif dev_kvm_accessible:
                    virt_type = "kvm"
                else:
                    virt_type = "hw_cpu_only"
            probe_status = "ok"
        except Exception:
            virt_type = "unknown"
            probe_status = "failed"

    elif system == "Windows":
        virt_type = "unknown"
        probe_status = "unsupported_in_script"

    return cpu_virt_flag, dev_kvm_accessible, virt_type, probe_status


def check_container_and_vms(system):
    container_engine = "none"
    container_ready = False
    details = {}

    docker_path = shutil.which("docker")
    podman_path = shutil.which("podman")
    limactl_path = shutil.which("limactl")
    colima_path = shutil.which("colima")

    details["limactl_installed"] = bool(limactl_path)
    details["colima_installed"] = bool(colima_path)
    details["docker_cli_installed"] = bool(docker_path)

    if docker_path:
        container_engine = "docker"
        try:
            res = subprocess.run(
                [docker_path, "info"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3
            )
            container_ready = (res.returncode == 0)
        except Exception:
            container_ready = False
    elif podman_path:
        container_engine = "podman"
        try:
            res = subprocess.run(
                [podman_path, "info"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3
            )
            container_ready = (res.returncode == 0)
        except Exception:
            container_ready = False

    return container_engine, container_ready, details


def get_target_disk_free(target_path):
    if not target_path or not os.path.exists(target_path):
        return None
    try:
        usage = shutil.disk_usage(target_path)
        return usage.free
    except Exception:
        return None


def inspect_host(target_dir=None):
    system = platform.system()
    machine = platform.machine()
    arch = "amd64" if machine in ("x86_64", "AMD64") else ("arm64" if machine in ("arm64", "aarch64") else machine)

    os_id = system.lower()
    os_version = None

    if system == "Darwin":
        os_id = "macos"
        mac_ver = platform.mac_ver()[0]
        os_version = mac_ver if mac_ver else None
    elif system == "Linux":
        if os.path.exists("/etc/os-release"):
            try:
                with open("/etc/os-release", "r", encoding="utf-8") as f:
                    for line in f:
                        if line.startswith("ID="):
                            os_id = line.strip().split("=")[1].strip('"')
                        elif line.startswith("VERSION_ID="):
                            os_version = line.strip().split("=")[1].strip('"')
            except Exception:
                pass
    elif system == "Windows":
        os_id = "windows"
        os_version = platform.version() or None
    else:
        os_id = system.lower()
        os_version = None

    cpu_cores = get_cpu_cores()
    total_ram_mb, avail_ram_mb, mem_status, mem_estimated = get_memory_info(system)
    cpu_virt_flag, dev_kvm_accessible, virt_type, virt_status = check_virtualization(system)
    container_engine, container_ready, vm_tools = check_container_and_vms(system)

    disk_free_bytes = get_target_disk_free(target_dir if target_dir else os.getcwd())

    notices = []
    if system == "Darwin":
        if not vm_tools.get("docker_cli_installed"):
            notices.append("未检测到 Docker CLI")
        elif not container_ready:
            notices.append("Docker CLI 存在但 Docker daemon 未响应或未运行")
        if not vm_tools.get("limactl_installed") and not vm_tools.get("colima_installed"):
            notices.append("未检测到 Lima/Colima 工具，macOS 独立 Linux guest 运行环境未就绪")
    elif system == "Linux":
        if not cpu_virt_flag:
            notices.append("CPU 硬件虚拟化标记未置位")
        if not dev_kvm_accessible:
            notices.append("/dev/kvm 不存在或当前用户无读写权限")
    elif system == "Windows":
        notices.append("Windows 平台探测未在此脚本中实现")

    # installation_status is strictly not_checked as this is a read-only inspection tool
    return {
        "schema_version": 1,
        "inspection_scope": "host_only_read_only",
        "installation_status": "not_checked",
        "os_id": os_id,
        "os_version": os_version,
        "architecture": arch,
        "cpu_cores": cpu_cores,
        "total_ram_mb": total_ram_mb,
        "available_ram_mb": avail_ram_mb,
        "memory_probe_status": mem_status,
        "available_ram_is_estimated": mem_estimated,
        "disk_free_bytes": disk_free_bytes,
        "cpu_virtualization_flag": cpu_virt_flag,
        "dev_kvm_accessible": dev_kvm_accessible,
        "virtualization_type": virt_type,
        "virtualization_probe_status": virt_status,
        "container_engine": container_engine,
        "container_engine_ready": container_ready,
        "vm_tools": vm_tools,
        "notices": notices
    }


def main():
    parser = argparse.ArgumentParser(description="AcornFox Desktop Preflight (Read-Only)")
    parser.add_argument("--summary", action="store_true", help="输出中文可读摘要（默认输出 JSON）")
    parser.add_argument("--path", default=None, help="目标检查目录路径")
    args = parser.parse_args()

    data = inspect_host(target_dir=args.path)

    if not args.summary:
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        print("==================================================")
        print("      AcornFox Desktop 宿主只读预检报告")
        print("==================================================")
        print(f"操作系统:       {data['os_id']} {data['os_version'] or '未知'} ({data['architecture']})")
        cores_str = f"{data['cpu_cores']} 核" if data['cpu_cores'] is not None else "未知"
        print(f"CPU 核心:       {cores_str}")

        total_str = f"{data['total_ram_mb']} MiB" if data['total_ram_mb'] is not None else "未知"
        avail_str = f"{data['available_ram_mb']} MiB" if data['available_ram_mb'] is not None else "未知"
        if data['available_ram_is_estimated']:
            avail_str += " (估算)"
        print(f"内存资源:       总计 {total_str} / 可用 {avail_str} [探针: {data['memory_probe_status']}]")

        disk_str = f"{data['disk_free_bytes'] // (1024 * 1024)} MiB" if data['disk_free_bytes'] is not None else "未知"
        print(f"磁盘空闲:       {disk_str}")

        cpu_virt = "置位" if data['cpu_virtualization_flag'] else "未置位"
        kvm_str = "可访问" if data['dev_kvm_accessible'] else "不可访问"
        print(f"虚拟化能力:     CPU指令 {cpu_virt} | /dev/kvm {kvm_str} ({data['virtualization_type']})")

        docker_str = "CLI已安装" if data['vm_tools'].get('docker_cli_installed') else "未安装"
        daemon_str = "响应正常" if data['container_engine_ready'] else "未运行/未响应"
        print(f"容器状态:       引擎 {data['container_engine']} ({docker_str}, Daemon {daemon_str})")
        print("--------------------------------------------------")
        print(f"产品安装状态:   {data['installation_status']} (本工具仅探查宿主, 不宣称可安装或已安装)")

        if data["notices"]:
            print("\n检查提示:")
            for n in data["notices"]:
                print(f"  [*] {n}")
        print("==================================================")


if __name__ == "__main__":
    main()
