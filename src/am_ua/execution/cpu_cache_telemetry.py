"""CPU Cache Hierarchy, False-Sharing, Set-Associative LRU & Roofline Hardware Telemetry (`am_ua.execution.cpu_cache_telemetry`).

Provides four deterministic, zero-token hardware telemetry and cache-optimization organs:
1. `CPUCacheTopologyProbe`: Host CPU cache hierarchy topology & optimal FP64 loop-tiling block size solver.
2. `CacheLineFalseSharingAnalyzer`: 64-byte cache-line false-sharing detector, padding synthesizer, and AoS-to-SoA advisor.
3. `SetAssociativeCacheSimulator`: Deterministic N-way set-associative LRU hardware cache simulator with AMAT & stride metrics.
4. `RooflineHardwareTelemetryModel`: Williams-Waterman-Patterson Roofline performance model and optimization prescriber.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple


@dataclass(frozen=True)
class CacheAddressDecomposition:
    """Decomposed memory address for a set-associative cache hierarchy."""

    address: int
    line_address: int
    tag: int
    set_index: int
    block_offset: int


def _normalize_positive_int(value: int, default: int, minimum: int = 1) -> int:
    """Coerce an integer parameter to a valid positive domain value."""
    try:
        coerced = int(value)
    except (TypeError, ValueError):
        return default
    return coerced if coerced >= minimum else minimum


class CPUCacheTopologyProbe:
    """Probes host CPU architecture and computes deterministic cache hierarchy parameters."""

    DEFAULT_PAGE_SIZE_BYTES: int = 4096
    FP64_ELEMENT_BYTES: int = 8

    @classmethod
    def probe_hierarchy(
        cls,
        *,
        l1d_kb: int = 32,
        l2_kb: int = 512,
        l3_kb: int = 16384,
        cache_line_bytes: int = 64,
    ) -> Dict[str, Any]:
        """Probe CPU architecture and compute L1d/L2/L3 byte/line capacities and optimal FP64 tile dimensions."""
        line_bytes = _normalize_positive_int(cache_line_bytes, 64, minimum=16)
        l1_kb_val = _normalize_positive_int(l1d_kb, 32, minimum=1)
        l2_kb_val = _normalize_positive_int(l2_kb, 512, minimum=l1_kb_val)
        l3_kb_val = _normalize_positive_int(l3_kb, 16384, minimum=l2_kb_val)

        l1d_bytes = l1_kb_val * 1024
        l2_bytes = l2_kb_val * 1024
        l3_bytes = l3_kb_val * 1024

        l1d_lines = l1d_bytes // line_bytes
        l2_lines = l2_bytes // line_bytes
        l3_lines = l3_bytes // line_bytes

        # For 3 dense FP64 tiles (A_tile, B_tile, C_tile) resident simultaneously in cache:
        # 3 * (B^*)^2 * 8 <= L1d_bytes  =>  B^* = floor(sqrt((L1d_bytes / 3) / 8))
        optimal_l1_tile_dim = max(
            1, int(math.floor(math.sqrt((l1d_bytes / 3.0) / float(cls.FP64_ELEMENT_BYTES))))
        )
        optimal_l2_tile_dim = max(
            1, int(math.floor(math.sqrt((l2_bytes / 3.0) / float(cls.FP64_ELEMENT_BYTES))))
        )
        fp64_per_line = max(1, line_bytes // cls.FP64_ELEMENT_BYTES)
        page_size = cls.DEFAULT_PAGE_SIZE_BYTES

        arch = platform.machine() or "x86_64"
        proc = platform.processor() or arch
        logical_cores = os.cpu_count() or 1
        pointer_bits = struct.calcsize("P") * 8
        int_object_bytes = sys.getsizeof(0)

        return {
            "ok": True,
            "architecture": arch,
            "processor": proc,
            "logical_cpu_count": int(logical_cores),
            "pointer_width_bits": int(pointer_bits),
            "python_int_object_bytes": int(int_object_bytes),
            "cache_line_bytes": line_bytes,
            "fp64_elements_per_cache_line": fp64_per_line,
            "page_size_bytes": page_size,
            "cache_lines_per_page": page_size // line_bytes,
            "l1d_kb": l1_kb_val,
            "l1d_bytes": l1d_bytes,
            "l1d_cache_lines": l1d_lines,
            "l2_kb": l2_kb_val,
            "l2_bytes": l2_bytes,
            "l2_cache_lines": l2_lines,
            "l3_kb": l3_kb_val,
            "l3_bytes": l3_bytes,
            "l3_cache_lines": l3_lines,
            "optimal_fp64_tile_block_dim": optimal_l1_tile_dim,
            "optimal_l2_fp64_tile_block_dim": optimal_l2_tile_dim,
            "l1_working_set_three_tiles_bytes": 3 * (optimal_l1_tile_dim ** 2) * cls.FP64_ELEMENT_BYTES,
        }

    @classmethod
    def probe_live_host_cache(cls) -> Dict[str, Any]:
        """Query REAL host silicon L1/L2/L3 cache hierarchy (Win32 CIM or Linux sysfs) with analytical tile sizing."""
        cpu_name = platform.processor() or platform.machine() or "unknown"
        phys_cores = os.cpu_count() or 1
        logical_cores = os.cpu_count() or 1
        l1d_kb = 32
        l2_kb = 512
        l3_kb = 16384
        source = "portable_defaults"

        if os.name == "nt":
            try:
                ps = (
                    "$p = Get-CimInstance Win32_Processor | Select-Object -First 1 Name,NumberOfCores,NumberOfLogicalProcessors,L2CacheSize,L3CacheSize; "
                    "$c = Get-CimInstance Win32_CacheMemory | Select-Object Level,MaxCacheSize; "
                    "@{proc=$p;cache=$c} | ConvertTo-Json -Compress"
                )
                proc = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", ps],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=6,
                    check=False,
                )
                if proc.returncode == 0 and proc.stdout.strip().startswith("{"):
                    data = json.loads(proc.stdout)
                    pinfo = data.get("proc") or {}
                    cpu_name = str(pinfo.get("Name") or cpu_name).strip()
                    phys_cores = max(1, int(pinfo.get("NumberOfCores") or phys_cores))
                    logical_cores = max(1, int(pinfo.get("NumberOfLogicalProcessors") or logical_cores))
                    if pinfo.get("L2CacheSize"):
                        l2_kb = max(64, int(pinfo["L2CacheSize"]) // phys_cores)
                    if pinfo.get("L3CacheSize"):
                        l3_kb = max(256, int(pinfo["L3CacheSize"]))
                    caches = data.get("cache") or []
                    if isinstance(caches, dict):
                        caches = [caches]
                    for entry in caches:
                        lvl = entry.get("Level")
                        sz = entry.get("MaxCacheSize")
                        if lvl == 3 and sz:
                            # Win32 Level 3 = L1 total (I+D) across physical cores
                            l1d_kb = max(16, (int(sz) // max(1, phys_cores)) // 2)
                    source = "win32_cim_silicon_probe"
            except Exception:
                pass
        else:
            cache_root = Path("/sys/devices/system/cpu/cpu0/cache")
            if cache_root.is_dir():
                for idx_dir in sorted(cache_root.glob("index*")):
                    try:
                        lvl = int((idx_dir / "level").read_text(encoding="utf-8").strip())
                        ctype = (idx_dir / "type").read_text(encoding="utf-8").strip().lower()
                        sz_str = (idx_dir / "size").read_text(encoding="utf-8").strip().upper()
                        sz_kb = int(sz_str[:-1]) * (1024 if sz_str.endswith("M") else 1)
                        if lvl == 1 and "data" in ctype:
                            l1d_kb = sz_kb
                        elif lvl == 2:
                            l2_kb = sz_kb
                        elif lvl == 3:
                            l3_kb = sz_kb
                        source = "linux_sysfs_silicon_probe"
                    except Exception:
                        continue

        base = cls.probe_hierarchy(l1d_kb=l1d_kb, l2_kb=l2_kb, l3_kb=l3_kb)
        base.update({
            "probe_source": source,
            "cpu_model": cpu_name,
            "physical_cores": phys_cores,
            "logical_cores": logical_cores,
            "smt_ratio": round(logical_cores / max(1, phys_cores), 2),
        })
        return base

    @classmethod
    def measure_memory_hierarchy_bandwidth(cls) -> Dict[str, Any]:
        """Measure real L1-resident (16KB), L2-resident (256KB), and DRAM (4MB) copy throughput in MB/s."""
        benchmarks: Dict[str, Dict[str, Any]] = {}
        for tier, sz_bytes, iters in (
            ("l1_16kb", 16 * 1024, 200),
            ("l2_256kb", 256 * 1024, 40),
            ("dram_4mb", 4 * 1024 * 1024, 6),
        ):
            src = bytearray(b"\x5a" * sz_bytes)
            dst = bytearray(sz_bytes)
            t0 = time.perf_counter()
            for _ in range(iters):
                dst[:] = src
            dt = max(1e-6, time.perf_counter() - t0)
            mb_moved = (sz_bytes * iters) / (1024.0 * 1024.0)
            benchmarks[tier] = {
                "working_set_bytes": sz_bytes,
                "iterations": iters,
                "elapsed_ms": round(dt * 1000.0, 3),
                "bandwidth_mbps": round(mb_moved / dt, 1),
            }
        return {"ok": True, "tiers": benchmarks}

    @classmethod
    def compute_loop_tiling_plan(
        cls,
        *,
        matrix_n: int = 128,
        l1d_kb: int = 32,
        l2_kb: int = 512,
        cache_line_bytes: int = 64,
    ) -> Dict[str, Any]:
        """Compute L1/L2 loop-tiling block dimensions and estimate cache miss reduction on matrix kernels."""
        hierarchy = cls.probe_hierarchy(
            l1d_kb=l1d_kb,
            l2_kb=l2_kb,
            cache_line_bytes=cache_line_bytes,
        )
        n_dim = _normalize_positive_int(matrix_n, 128, minimum=4)
        b_l1 = int(hierarchy["optimal_fp64_tile_block_dim"])
        b_l2 = int(hierarchy["optimal_l2_fp64_tile_block_dim"])
        fp64_per_line = int(hierarchy["fp64_elements_per_cache_line"])

        # Naive column-strided inner loop incurs ~1 miss per access on matrix B when N*8 > L1d,
        # whereas tiled execution amortizes misses by a factor of min(b_l1, fp64_per_line).
        reuse_factor = max(1.0, min(float(b_l1), float(fp64_per_line)))
        naive_estimated_miss_rate_pct = 62.5
        tiled_estimated_miss_rate_pct = round(naive_estimated_miss_rate_pct / reuse_factor, 4)
        miss_reduction_pct = round(
            ((naive_estimated_miss_rate_pct - tiled_estimated_miss_rate_pct) / naive_estimated_miss_rate_pct) * 100.0,
            2,
        )

        return {
            "ok": True,
            "matrix_dimension_n": n_dim,
            "l1_tile_block_dim": b_l1,
            "l2_tile_block_dim": b_l2,
            "cache_line_bytes": int(hierarchy["cache_line_bytes"]),
            "fp64_elements_per_cache_line": fp64_per_line,
            "naive_estimated_miss_rate_pct": naive_estimated_miss_rate_pct,
            "tiled_estimated_miss_rate_pct": tiled_estimated_miss_rate_pct,
            "expected_miss_reduction_pct": miss_reduction_pct,
            "hierarchy": hierarchy,
        }


def _extract_field_spec(raw_field: Dict[str, Any], index: int) -> Tuple[str, int, Optional[str]]:
    """Normalize a single struct field specification dict."""
    name = str(raw_field.get("name") or f"field_{index}").strip() or f"field_{index}"
    raw_size = raw_field.get("size_bytes", raw_field.get("size", 8))
    size_bytes = _normalize_positive_int(raw_size, 8, minimum=1)
    raw_writer = raw_field.get("writer_thread", raw_field.get("thread", raw_field.get("writer")))
    writer_thread = str(raw_writer).strip() if raw_writer is not None and str(raw_writer).strip() else None
    return name, size_bytes, writer_thread


def _detect_line_collisions(
    line_to_fields: Dict[int, List[Dict[str, Any]]],
    line_bytes: int,
) -> List[Dict[str, Any]]:
    """Identify cache lines shared by two or more distinct writer threads."""
    collisions: List[Dict[str, Any]] = []
    for line_idx in sorted(line_to_fields.keys()):
        occupants = line_to_fields[line_idx]
        writers: List[str] = []
        for item in occupants:
            w_thread = item.get("writer_thread")
            if isinstance(w_thread, str) and w_thread and w_thread not in writers:
                writers.append(w_thread)
        if len(writers) > 1:
            collisions.append(
                {
                    "cache_line_index": line_idx,
                    "byte_range": [line_idx * line_bytes, (line_idx + 1) * line_bytes - 1],
                    "conflicting_writer_threads": writers,
                    "conflicting_fields": [str(item["name"]) for item in occupants if item.get("writer_thread")],
                    "severity": "CRITICAL_FALSE_SHARING",
                }
            )
    return collisions


def _group_fields_by_writer(
    normalized_fields: Sequence[Tuple[str, int, Optional[str]]],
) -> Tuple[List[Optional[str]], Dict[Optional[str], List[Tuple[str, int, Optional[str]]]]]:
    """Group struct fields by writer_thread placing hot writer threads ahead of shared/read-only fields."""
    writer_order: List[Optional[str]] = []
    grouped: Dict[Optional[str], List[Tuple[str, int, Optional[str]]]] = {}
    for spec in normalized_fields:
        writer = spec[2]
        if writer not in grouped:
            writer_order.append(writer)
            grouped[writer] = []
        grouped[writer].append(spec)
    hot_writers: List[Optional[str]] = []
    readonly_writers: List[Optional[str]] = []
    for writer in writer_order:
        if writer is not None:
            hot_writers.append(writer)
        else:
            readonly_writers.append(writer)
    return hot_writers + readonly_writers, grouped


def _make_padding_entry(pad_name: str, current_offset: int, pad_bytes: int, line_bytes: int) -> Dict[str, Any]:
    """Create a synthetic cache-line padding record."""
    return {
        "name": pad_name,
        "size_bytes": pad_bytes,
        "writer_thread": None,
        "is_padding": True,
        "start_offset": current_offset,
        "end_offset": current_offset + pad_bytes,
        "cache_line_index": current_offset // line_bytes,
    }


def _synthesize_padded_layout(
    normalized_fields: Sequence[Tuple[str, int, Optional[str]]],
    line_bytes: int,
) -> Tuple[List[Dict[str, Any]], int, List[str]]:
    """Reorder fields by writer_thread and insert alignas(cache_line_bytes) padding between writer domains."""
    ordered_groups, grouped = _group_fields_by_writer(normalized_fields)

    optimized: List[Dict[str, Any]] = []
    directives: List[str] = []
    current_offset = 0
    padding_inserted = 0
    pad_counter = 0

    for group_idx, writer in enumerate(ordered_groups):
        remainder = current_offset % line_bytes
        if group_idx > 0 and writer is not None and remainder != 0:
            pad_bytes = line_bytes - remainder
            optimized.append(_make_padding_entry(f"_pad_cacheline_{pad_counter}", current_offset, pad_bytes, line_bytes))
            pad_counter += 1
            current_offset += pad_bytes
            padding_inserted += pad_bytes

        for f_name, f_size, f_writer in grouped[writer]:
            rem_in_line = line_bytes - (current_offset % line_bytes)
            if f_size <= line_bytes and f_size > rem_in_line:
                optimized.append(_make_padding_entry(f"_pad_align_{pad_counter}", current_offset, rem_in_line, line_bytes))
                pad_counter += 1
                current_offset += rem_in_line
                padding_inserted += rem_in_line

            start_off = current_offset
            end_off = current_offset + f_size
            is_line_aligned_writer = (start_off % line_bytes == 0) and (f_writer is not None)
            optimized.append(
                {
                    "name": f_name,
                    "size_bytes": f_size,
                    "writer_thread": f_writer,
                    "is_padding": False,
                    "start_offset": start_off,
                    "end_offset": end_off,
                    "cache_line_index": start_off // line_bytes,
                    "alignas": line_bytes if is_line_aligned_writer else None,
                }
            )
            if is_line_aligned_writer:
                directives.append(f"alignas({line_bytes}) /* thread={f_writer} */ {f_name}")
            current_offset = end_off

    return optimized, padding_inserted, directives


class CacheLineFalseSharingAnalyzer:
    """Analyzes struct byte layouts for 64-byte cache-line straddling and multi-thread false sharing."""

    @classmethod
    def analyze_struct_layout(
        cls,
        fields: Sequence[Dict[str, Any]],
        *,
        cache_line_bytes: int = 64,
    ) -> Dict[str, Any]:
        """Compute field byte offsets, cache-line straddling, false-sharing collisions, and padded layout."""
        line_bytes = _normalize_positive_int(cache_line_bytes, 64, minimum=16)
        normalized: List[Tuple[str, int, Optional[str]]] = [
            _extract_field_spec(dict(raw), idx) for idx, raw in enumerate(fields)
        ]

        field_layout: List[Dict[str, Any]] = []
        straddling_fields: List[Dict[str, Any]] = []
        line_to_fields: Dict[int, List[Dict[str, Any]]] = {}
        offset = 0

        for name, size_bytes, writer_thread in normalized:
            start_off = offset
            end_off = offset + size_bytes
            start_line = start_off // line_bytes
            end_line = (end_off - 1) // line_bytes
            straddles = end_line > start_line
            spanned_lines = list(range(start_line, end_line + 1))

            record: Dict[str, Any] = {
                "name": name,
                "size_bytes": size_bytes,
                "writer_thread": writer_thread,
                "start_offset": start_off,
                "end_offset": end_off,
                "cache_line_index": start_line,
                "end_cache_line_index": end_line,
                "spanned_cache_lines": spanned_lines,
                "straddles_cache_line": straddles,
            }
            field_layout.append(record)
            if straddles:
                straddling_fields.append(record)
            for l_idx in spanned_lines:
                line_to_fields.setdefault(l_idx, []).append(record)
            offset = end_off

        collisions = _detect_line_collisions(line_to_fields, line_bytes)
        optimized_layout, padding_bytes, directives = _synthesize_padded_layout(normalized, line_bytes)
        total_original_bytes = offset
        total_optimized_bytes = sum(int(item["size_bytes"]) for item in optimized_layout)

        return {
            "ok": True,
            "cache_line_bytes": line_bytes,
            "field_count": len(field_layout),
            "original_size_bytes": total_original_bytes,
            "original_cache_lines_spanned": (
                ((total_original_bytes - 1) // line_bytes) + 1 if total_original_bytes > 0 else 0
            ),
            "field_layout": field_layout,
            "straddling_fields": straddling_fields,
            "straddling_count": len(straddling_fields),
            "false_sharing_detected": len(collisions) > 0,
            "collision_count": len(collisions),
            "false_sharing_collisions": collisions,
            "optimized_layout": optimized_layout,
            "optimized_size_bytes": total_optimized_bytes,
            "padding_bytes_inserted": padding_bytes,
            "alignas_64_directives": directives,
            "soa_recommendation": (
                "Convert Array-of-Structs (AoS) to Struct-of-Arrays (SoA) and isolate each writer_thread "
                f"into dedicated alignas({line_bytes}) contiguous buffers to eliminate MESI invalidation storms."
            ),
        }


def _compute_stride_metrics(addresses: Sequence[int], line_bytes: int) -> Dict[str, Any]:
    """Compute spatial locality and stride efficiency across consecutive memory accesses."""
    if len(addresses) <= 1:
        return {
            "stride_samples": 0,
            "average_stride_bytes": 0.0,
            "same_cache_line_ratio": 1.0,
            "unit_line_stride_ratio": 1.0,
            "spatial_stride_efficiency": 1.0,
        }

    total_deltas = len(addresses) - 1
    abs_strides: List[int] = []
    same_line_hits = 0
    near_line_hits = 0

    for idx in range(total_deltas):
        curr_addr = int(addresses[idx])
        next_addr = int(addresses[idx + 1])
        delta = abs(next_addr - curr_addr)
        abs_strides.append(delta)
        curr_line = curr_addr // line_bytes
        next_line = next_addr // line_bytes
        line_delta = abs(next_line - curr_line)
        if line_delta == 0:
            same_line_hits += 1
            near_line_hits += 1
        elif line_delta == 1:
            near_line_hits += 1

    avg_stride = sum(abs_strides) / float(total_deltas)
    same_line_ratio = same_line_hits / float(total_deltas)
    unit_stride_ratio = near_line_hits / float(total_deltas)

    return {
        "stride_samples": total_deltas,
        "average_stride_bytes": round(avg_stride, 2),
        "same_cache_line_ratio": round(same_line_ratio, 4),
        "unit_line_stride_ratio": round(unit_stride_ratio, 4),
        "spatial_stride_efficiency": round(unit_stride_ratio, 4),
    }


class SetAssociativeCacheSimulator:
    """Deterministic N-way set-associative LRU hardware cache simulator."""

    L1_HIT_CYCLES: float = 4.0
    L2_HIT_CYCLES: float = 12.0
    RAM_PENALTY_CYCLES: float = 200.0
    DEFAULT_L2_HIT_PROB_ON_L1_MISS: float = 0.85

    @classmethod
    def decompose_address(
        cls,
        address: int,
        *,
        line_size_bytes: int = 64,
        num_sets: int = 64,
    ) -> CacheAddressDecomposition:
        """Decompose a byte address into `(tag, set_index, block_offset)`."""
        addr = max(0, int(address))
        line_bytes = _normalize_positive_int(line_size_bytes, 64, minimum=1)
        sets = _normalize_positive_int(num_sets, 64, minimum=1)
        line_addr = addr // line_bytes
        block_offset = addr % line_bytes
        set_index = line_addr % sets
        tag = line_addr // sets
        return CacheAddressDecomposition(
            address=addr,
            line_address=line_addr,
            tag=tag,
            set_index=set_index,
            block_offset=block_offset,
        )

    @classmethod
    def simulate_access_trace(
        cls,
        addresses: Sequence[int],
        *,
        cache_size_bytes: int = 32768,
        line_size_bytes: int = 64,
        associativity: int = 8,
    ) -> Dict[str, Any]:
        """Simulate an address trace through an N-way set-associative LRU cache."""
        line_bytes = _normalize_positive_int(line_size_bytes, 64, minimum=1)
        ways = _normalize_positive_int(associativity, 8, minimum=1)
        total_cache_bytes = _normalize_positive_int(cache_size_bytes, 32768, minimum=line_bytes * ways)
        total_lines = max(ways, total_cache_bytes // line_bytes)
        num_sets = max(1, total_lines // ways)

        # Each set maintains an LRU list of tags: index 0 is LRU, index -1 is MRU
        sets_lru: Dict[int, List[int]] = {s_idx: [] for s_idx in range(num_sets)}
        seen_line_addresses: Set[int] = set()

        hits = 0
        misses = 0
        compulsory_misses = 0
        capacity_or_conflict_misses = 0
        evictions = 0
        trace_sample: List[Dict[str, Any]] = []

        for step_idx, raw_addr in enumerate(addresses):
            decomp = cls.decompose_address(
                int(raw_addr),
                line_size_bytes=line_bytes,
                num_sets=num_sets,
            )
            way_list = sets_lru[decomp.set_index]
            if decomp.tag in way_list:
                hits += 1
                way_list.remove(decomp.tag)
                way_list.append(decomp.tag)
                outcome = "HIT"
            else:
                misses += 1
                if decomp.line_address not in seen_line_addresses:
                    compulsory_misses += 1
                    seen_line_addresses.add(decomp.line_address)
                    outcome = "MISS_COMPULSORY"
                else:
                    capacity_or_conflict_misses += 1
                    outcome = "MISS_CONFLICT_OR_CAPACITY"

                if len(way_list) >= ways:
                    way_list.pop(0)
                    evictions += 1
                way_list.append(decomp.tag)

            if step_idx < 32:
                trace_sample.append(
                    {
                        "step": step_idx,
                        "address": decomp.address,
                        "tag": decomp.tag,
                        "set_index": decomp.set_index,
                        "block_offset": decomp.block_offset,
                        "outcome": outcome,
                    }
                )

        total_accesses = len(addresses)
        hit_rate = (hits / float(total_accesses)) if total_accesses > 0 else 1.0
        miss_rate = 1.0 - hit_rate
        hit_rate_pct = round(hit_rate * 100.0, 4)
        miss_rate_pct = round(miss_rate * 100.0, 4)

        # Average Memory Access Time (AMAT) with L1=4, L2=12 (85% of L1 misses), RAM=200 (15% of L1 misses)
        expected_miss_penalty = (
            cls.DEFAULT_L2_HIT_PROB_ON_L1_MISS * cls.L2_HIT_CYCLES
            + (1.0 - cls.DEFAULT_L2_HIT_PROB_ON_L1_MISS) * cls.RAM_PENALTY_CYCLES
        )
        amat_cycles = round(cls.L1_HIT_CYCLES + miss_rate * expected_miss_penalty, 4)
        stride_metrics = _compute_stride_metrics(addresses, line_bytes)

        return {
            "ok": True,
            "cache_size_bytes": total_cache_bytes,
            "line_size_bytes": line_bytes,
            "associativity": ways,
            "num_sets": num_sets,
            "total_cache_lines": num_sets * ways,
            "total_accesses": total_accesses,
            "hits": hits,
            "misses": misses,
            "compulsory_misses": compulsory_misses,
            "capacity_or_conflict_misses": capacity_or_conflict_misses,
            "evictions": evictions,
            "hit_rate_pct": hit_rate_pct,
            "miss_rate_pct": miss_rate_pct,
            "amat_cycles": amat_cycles,
            "latency_model_cycles": {
                "l1_hit_cycles": int(cls.L1_HIT_CYCLES),
                "l2_hit_cycles": int(cls.L2_HIT_CYCLES),
                "ram_access_cycles": int(cls.RAM_PENALTY_CYCLES),
            },
            "spatial_stride_efficiency": stride_metrics["spatial_stride_efficiency"],
            "stride_analysis": stride_metrics,
            "trace_sample": trace_sample,
        }


def _synthesize_roofline_prescriptions(
    *,
    regime: str,
    arithmetic_intensity: float,
    ridge_point: float,
    efficiency_pct: float,
) -> List[str]:
    """Generate deterministic hardware optimization prescriptions based on Roofline coordinates."""
    prescriptions: List[str] = []
    if regime == "MEMORY_BANDWIDTH_BOUND":
        prescriptions.append(
            f"Loop Tiling / Cache Blocking: Raise arithmetic intensity ({arithmetic_intensity:.3f} -> >= {ridge_point:.2f} FLOP/Byte) "
            "by keeping working blocks inside L1d/L2 cache."
        )
        prescriptions.append(
            "Data Layout SoA Transformation: Pack hot fields into contiguous Struct-of-Arrays buffers "
            "to maximize 64-byte cache-line spatial utilization."
        )
        prescriptions.append(
            "Hardware Stream Prefetching & Loop Fusion: Fuse producer-consumer loops to eliminate intermediate DRAM round-trips."
        )
    else:
        prescriptions.append(
            "SIMD Vectorization (AVX-512 / NEON): Saturate vector execution ports with aligned 64-byte packed FP64/FP32 loads."
        )
        prescriptions.append(
            "FMA Instruction Fusion & Loop Unrolling: Unroll inner reduction loops 4x-8x to hide FMA pipeline latency."
        )
    if efficiency_pct < 75.0:
        prescriptions.append(
            "Thread Affinity & NUMA Pinning: Pin worker threads to physical cores sharing L2/L3 slices to avoid cross-socket traffic."
        )
    return prescriptions


class RooflineHardwareTelemetryModel:
    """Evaluates compute kernels against the Williams-Waterman-Patterson Roofline performance model."""

    @classmethod
    def evaluate_kernel(
        cls,
        *,
        flops: int,
        bytes_transferred: int,
        elapsed_s: float,
        peak_gflops: float = 512.0,
        peak_bandwidth_gbps: float = 64.0,
    ) -> Dict[str, Any]:
        """Compute Arithmetic Intensity, Ridge Point, Roofline Ceiling, regime classification, and prescriptions."""
        safe_flops = max(0, int(flops))
        safe_bytes = max(1, int(bytes_transferred))
        safe_elapsed = max(1e-12, float(elapsed_s))
        safe_peak_gflops = max(1e-6, float(peak_gflops))
        safe_peak_bw = max(1e-6, float(peak_bandwidth_gbps))

        # Arithmetic Intensity I = FLOPs / Bytes
        arithmetic_intensity = safe_flops / float(safe_bytes)
        # Ridge Point I_ridge = Peak_GFLOPs / Peak_BW_GBps
        ridge_point = safe_peak_gflops / safe_peak_bw
        # Roofline Attainable Ceiling P_max = min(Peak_GFLOPs, I * Peak_BW_GBps)
        bandwidth_ceiling_gflops = arithmetic_intensity * safe_peak_bw
        attainable_gflops = min(safe_peak_gflops, bandwidth_ceiling_gflops)

        # Achieved throughput
        achieved_gflops = (safe_flops / safe_elapsed) / 1e9
        achieved_bandwidth_gbps = (safe_bytes / safe_elapsed) / 1e9

        regime = "MEMORY_BANDWIDTH_BOUND" if arithmetic_intensity < ridge_point else "COMPUTE_BOUND"
        roofline_efficiency_pct = (
            min(100.0, (achieved_gflops / attainable_gflops) * 100.0) if attainable_gflops > 0 else 0.0
        )
        peak_compute_utilization_pct = min(100.0, (achieved_gflops / safe_peak_gflops) * 100.0)
        bandwidth_utilization_pct = min(100.0, (achieved_bandwidth_gbps / safe_peak_bw) * 100.0)

        prescriptions = _synthesize_roofline_prescriptions(
            regime=regime,
            arithmetic_intensity=arithmetic_intensity,
            ridge_point=ridge_point,
            efficiency_pct=roofline_efficiency_pct,
        )

        return {
            "ok": True,
            "flops": safe_flops,
            "bytes_transferred": safe_bytes,
            "elapsed_s": safe_elapsed,
            "peak_gflops": round(safe_peak_gflops, 4),
            "peak_bandwidth_gbps": round(safe_peak_bw, 4),
            "arithmetic_intensity_flops_per_byte": round(arithmetic_intensity, 6),
            "ridge_point_flops_per_byte": round(ridge_point, 6),
            "attainable_gflops": round(attainable_gflops, 6),
            "roofline_ceiling_gflops": round(attainable_gflops, 6),
            "achieved_gflops": round(achieved_gflops, 6),
            "achieved_bandwidth_gbps": round(achieved_bandwidth_gbps, 6),
            "bottleneck_regime": regime,
            "roofline_efficiency_pct": round(roofline_efficiency_pct, 4),
            "peak_compute_utilization_pct": round(peak_compute_utilization_pct, 4),
            "bandwidth_utilization_pct": round(bandwidth_utilization_pct, 4),
            "prescriptions": prescriptions,
            "timestamp_ns": time.time_ns(),
        }
