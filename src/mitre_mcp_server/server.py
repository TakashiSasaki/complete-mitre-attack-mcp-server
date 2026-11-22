from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, List, Literal, Tuple, Dict, Any, Optional
import os
import re
import sys

from mitreattack import download_stix, release_info
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from mitreattack.stix20 import MitreAttackData
from pydantic import Field



# ---------------------------------------------------------------------------
# Configuration & shared constants
# ---------------------------------------------------------------------------

# Domains we support
DOMAINS: List[str] = ["enterprise", "mobile", "ics"]

DEFAULT_PAGE_LIMIT = 100
MAX_PAGE_LIMIT = 200
MAX_BATCH_DETECTION_TECHNIQUES = 50

_TECHNIQUE_ATTACK_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
_TECHNIQUE_STIX_ID_RE = re.compile(
    r"^attack-pattern--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_DETECTION_COVERAGE_CAVEAT = (
    "ATT&CK detection strategies, analytics, and data components provide reference "
    "detection guidance and telemetry mappings, not a guarantee of detection coverage "
    "or effectiveness in any specific environment. Technique associations in ATT&CK "
    "do not constitute proof of specific CVE exploitation."
)
_MITIGATION_COVERAGE_CAVEAT = (
    "ATT&CK mitigations (course-of-action, Mxxxx) provide reference defensive guidance "
    "for reducing risk or addressing technique behaviors, not a guarantee of prevention "
    "or complete remediation in any specific environment. Technique associations in "
    "ATT&CK do not constitute proof of specific CVE exploitation."
)

PageLimit = Annotated[
    int,
    Field(
        default=DEFAULT_PAGE_LIMIT,
        ge=1,
        le=MAX_PAGE_LIMIT,
        description=f"Maximum number of items to return per page (1-{MAX_PAGE_LIMIT}).",
    ),
]
PageOffset = Annotated[
    int,
    Field(
        default=0,
        ge=0,
        description="Zero-based starting index for pagination (>= 0).",
    ),
]
AttributionFilter = Annotated[
    Literal["all", "direct", "campaign"],
    Field(
        default="all",
        description=(
            "Filter techniques by attribution provenance: 'all' (default), "
            "'direct' (direct group uses, including 'both'), or "
            "'campaign' (campaign-attributed uses, including 'both')."
        ),
    ),
]

_VALID_ATTRIBUTION_FILTERS = ("all", "direct", "campaign")
_VALID_BATCH_DETAIL_LEVELS = ("compact", "full")

BatchDetailLevel = Annotated[
    Literal["compact", "full"],
    Field(
        default="compact",
        description=(
            "Batch response detail level: 'compact' (default; deduplicated ID-indexed "
            "graph with names, platforms, adjacency edges, and provenance) or 'full' "
            "(includes STIX IDs, per-technique derived ID lists, and log sources)."
        ),
    ),
]

CrossDomainDetailLevel = Annotated[
    Literal["compact", "full"],
    Field(
        default="full",
        description=(
            "Cross-domain (`domain='all'`) response detail level: 'full' (default; preserves "
            "legacy per-domain provenance in `domain_status` and `limitations` in `metadata`) "
            "or 'compact' (deduplicates shared release/provenance into `metadata` with "
            "`source_url_template` while preserving per-domain status, match counts, failure "
            "differentiation, and all technique records). Ignored for single-domain calls."
        ),
    ),
]


def _validate_cross_domain_detail_level(detail_level: str) -> str:
    """Validate and normalize cross-domain search detail_level to 'compact' or 'full'."""
    if not isinstance(detail_level, str):
        raise ValueError(
            f"Invalid detail_level {detail_level!r}: "
            f"must be one of {', '.join(_VALID_BATCH_DETAIL_LEVELS)}."
        )
    normalized = detail_level.strip().lower()
    if normalized not in _VALID_BATCH_DETAIL_LEVELS:
        raise ValueError(
            f"Invalid detail_level {detail_level!r}: "
            f"must be one of {', '.join(_VALID_BATCH_DETAIL_LEVELS)}."
        )
    return normalized


def _validate_attribution_filter(attribution_filter: str) -> str:
    """Validate and normalize attribution_filter to 'all', 'direct', or 'campaign'."""
    if not isinstance(attribution_filter, str):
        raise ValueError(
            f"Invalid attribution_filter {attribution_filter!r}: "
            f"must be one of {', '.join(_VALID_ATTRIBUTION_FILTERS)}."
        )
    normalized = attribution_filter.strip().lower()
    if normalized not in _VALID_ATTRIBUTION_FILTERS:
        raise ValueError(
            f"Invalid attribution_filter {attribution_filter!r}: "
            f"must be one of {', '.join(_VALID_ATTRIBUTION_FILTERS)}."
        )
    return normalized


def _matches_attribution_filter(attribution_source: str, attribution_filter: str) -> bool:
    """Return True if an entry's attribution_source satisfies attribution_filter."""
    if attribution_filter == "all":
        return True
    if attribution_filter == "direct":
        return attribution_source in ("direct", "both")
    if attribution_filter == "campaign":
        return attribution_source in ("campaign", "both")
    return True


def _validate_pagination(limit: int, offset: int) -> Tuple[int, int]:
    """Validate pagination bounds (offset >= 0, 1 <= limit <= MAX_PAGE_LIMIT)."""
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError(f"Invalid offset {offset!r}: must be a non-negative integer (>= 0).")
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1 or limit > MAX_PAGE_LIMIT:
        raise ValueError(
            f"Invalid limit {limit!r}: must be an integer between 1 and {MAX_PAGE_LIMIT}."
        )
    return limit, offset


def _paginate_items(
    items: List[Any],
    limit: int = DEFAULT_PAGE_LIMIT,
    offset: int = 0,
) -> Tuple[List[Any], int, int, int, bool, Optional[int]]:
    """Slice a deterministically ordered list and return (page, total_count, offset, limit, has_more, next_offset)."""
    safe_limit, safe_offset = _validate_pagination(limit, offset)
    total_count = len(items)
    page = items[safe_offset : safe_offset + safe_limit]
    has_more = (safe_offset + len(page)) < total_count
    next_offset = (safe_offset + len(page)) if has_more else None
    return page, total_count, safe_offset, safe_limit, has_more, next_offset


def _attack_id_sort_key(
    attack_id: Optional[str],
    name: Optional[str],
    stix_id: Optional[str],
) -> Tuple[int, str, str, str]:
    """Deterministic ascending sort key: attack_id first (non-empty before missing), then name, then stix_id."""
    aid = str(attack_id or "").strip()
    return (
        0 if aid else 1,
        aid.upper(),
        str(name or "").lower(),
        str(stix_id or ""),
    )


def _classify_group_technique_attribution(
    relationships: List[Dict[str, Any]],
    group_stix_id: Optional[str],
) -> str:
    """Classify a group->technique entry's attribution provenance as 'direct', 'campaign', or 'both'."""
    has_direct = False
    has_campaign = False
    for rel in relationships:
        r_type = rel.get("relationship_type")
        src = str(rel.get("source_ref") or "")
        if r_type == "uses" and (
            (group_stix_id and src == group_stix_id) or src.startswith("intrusion-set--")
        ):
            has_direct = True
        elif r_type == "attributed-to" or src.startswith("campaign--"):
            has_campaign = True
    if has_direct and has_campaign:
        return "both"
    if has_campaign:
        return "campaign"
    return "direct"


def _format_rel_edge(rel: Any, include_description: bool = True) -> Dict[str, Any]:
    """Serialize a STIX relationship object/dict into a uniform edge dict."""
    if isinstance(rel, dict):
        r_id = rel.get("id")
        r_type = rel.get("relationship_type")
        r_desc = rel.get("description") if include_description else None
        r_source = rel.get("source_ref")
        r_target = rel.get("target_ref")
    else:
        r_id = getattr(rel, "id", None)
        r_type = getattr(rel, "relationship_type", None)
        r_desc = getattr(rel, "description", None) if include_description else None
        r_source = getattr(rel, "source_ref", None)
        r_target = getattr(rel, "target_ref", None)
    return {
        "stix_id": r_id,
        "relationship_type": r_type,
        "description": r_desc,
        "source_ref": r_source,
        "target_ref": r_target,
    }

APP_NAME = "mitre-mcp-server"

DATA_DIR: Path = Path(
    os.getenv(
        "MITRE_MCP_DATA_DIR",
        Path.home() / f".{APP_NAME}" / "data",
    )
).expanduser()


def get_version_dir() -> Path:
    """Return the versioned directory like DATA_DIR/v12.2."""
    return DATA_DIR / f"v{release_info.LATEST_VERSION}"


def get_stix_path(domain: str) -> Path:
    """Return the expected STIX JSON path for a given domain."""
    domain_key = f"{domain}-attack"
    return get_version_dir() / f"{domain_key}.json"


# ---------------------------------------------------------------------------
# Download helpers
# ---------------------------------------------------------------------------

def check_existing_data() -> List[str]:
    """Check which domains already have data downloaded.

    Returns:
        List of domain names that have existing data files.
    """
    existing_domains: List[str] = []

    for domain in DOMAINS:
        if get_stix_path(domain).exists():
            existing_domains.append(domain)

    return existing_domains


def download_domain_data(domain: str, force: bool = False) -> Tuple[str, Path]:
    """Download STIX data for a specific domain.

    Args:
        domain: Domain name ('enterprise', 'mobile', or 'ics')
        force: If True, download even if file already exists.

    Returns:
        Tuple of (domain, file_path) for the downloaded file.

    Raises:
        ValueError: If domain is not valid.
        RuntimeError: If download appears to succeed but file is missing.
    """
    if domain not in DOMAINS:
        raise ValueError(f"Invalid domain '{domain}'. Must be one of: {DOMAINS}")

    stix_path = get_stix_path(domain)

    # If file already exists and we're not forcing, just return it
    if stix_path.exists() and not force:
        return (domain, stix_path)

    # Get expected hash and version info
    releases = release_info.STIX21[domain]
    known_hash = releases[release_info.LATEST_VERSION]

    # Ensure base data directory exists
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Download STIX data into DATA_DIR (mitreattack will create the v<version> dir)
    download_stix.download_stix(
        stix_version="2.1",
        domain=domain,
        download_dir=str(DATA_DIR),
        release=release_info.LATEST_VERSION,
        known_hash=known_hash,
    )

    # Verify the file exists where we expect it
    if not stix_path.exists():
        raise RuntimeError(f"Download completed but file not found at {stix_path}")

    return (domain, stix_path)


def download_all_domains(force: bool = False) -> List[Tuple[str, Path]]:
    """Download STIX data for all domains (with caching).

    Args:
        force: If True, re-download even if files exist.

    Returns:
        List of tuples containing (domain, file_path) for each domain.
    """
    # Ensure base directory exists
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    downloaded_files: List[Tuple[str, Path]] = []

    for domain in DOMAINS:
        try:
            domain_data = download_domain_data(domain, force=force)
            downloaded_files.append(domain_data)
        except Exception:
            # You can add logging here later if you want
            pass

    return downloaded_files

# ---------------------------------------------------------------------------
# In-memory STIX loading helpers
# ---------------------------------------------------------------------------

# Cache of MitreAttackData objects keyed by e.g. "enterprise-attack"
attack_data: Dict[str, MitreAttackData] = {}

# Simple list of domains that have been successfully loaded
_loaded_domains: List[str] = []
_loaded_at: Dict[str, str] = {}

_SOURCE_INDEX_URL = "https://github.com/mitre-attack/attack-stix-data/blob/master/index.md"
_SOURCE_REPOSITORY_URL = "https://github.com/mitre-attack/attack-stix-data"
_KNOWN_SOURCE_RELEASE_DATES: Dict[str, str] = {
    "20.1": "2026-11-05",
}


def load_domain(domain: str) -> bool:
    """
    Load STIX data for a specific domain into memory.

    Args:
        domain: Domain name ('enterprise', 'mobile', or 'ics')

    Returns:
        True if loaded successfully, False otherwise.

    Raises:
        ValueError: If the domain is invalid.
        FileNotFoundError: If the expected STIX file is missing.
        RuntimeError: If MitreAttackData fails to load.
    """
    if domain not in DOMAINS:
        raise ValueError(f"Invalid domain '{domain}'. Must be one of: {DOMAINS}")

    domain_key = f"{domain}-attack"

    # Already loaded
    if domain_key in attack_data:
        return True

    stix_path = get_stix_path(domain)
    if not stix_path.exists():
        raise FileNotFoundError(
            f"STIX data file not found at {stix_path}. "
            "Ensure STIX data has been downloaded first (e.g., via download_all_domains "
            "or by starting the server once and checking get_data_stats)."
        )

    try:
        attack_data[domain_key] = MitreAttackData(str(stix_path))
        if domain not in _loaded_domains:
            _loaded_domains.append(domain)
        _loaded_at.setdefault(
            domain, datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        )
        return True
    except Exception as e:
        raise RuntimeError(f"Failed to load {domain} domain data: {e}") from e


def load_all_domains() -> List[str]:
    """
    Load STIX data for all available domains into memory.

    Returns:
        List of successfully loaded domain names.
    """
    loaded: List[str] = []
    for domain in DOMAINS:
        try:
            if load_domain(domain):
                loaded.append(domain)
        except Exception as e:
            # For now, just warn; you can hook this into proper logging later
            print(f"Warning: Could not load {domain} domain: {e}", file=sys.stderr)
    return loaded


def get_attack_data(domain: str = "enterprise") -> MitreAttackData:
    """
    Get the MitreAttackData object for a specific domain.

    Args:
        domain: Domain name (default: 'enterprise')

    Returns:
        MitreAttackData object for the specified domain.

    This will attempt to load the domain if it has not been loaded yet.
    """
    domain = (domain or "enterprise").strip().lower()
    domain_key = f"{domain}-attack"

    if domain_key not in attack_data:
        # This will raise if the file is missing or invalid
        load_domain(domain)

    return attack_data[domain_key]


def get_loaded_domains() -> List[str]:
    """
    Get a copy of the list of currently loaded domains.
    """
    return _loaded_domains.copy()


def _build_domain_provenance(
    domain: str,
    version: Optional[str] = None,
    stix_path: Optional[Path] = None,
    exists: Optional[bool] = None,
) -> Dict[str, Any]:
    """Build grounded release, origin, and freshness provenance for a domain."""
    if stix_path is None:
        stix_path = get_stix_path(domain)
    if exists is None:
        exists = stix_path.exists()

    limitations = [
        "Serves the local STIX bundle pinned by mitreattack-python (release_info.LATEST_VERSION); does not poll upstream GitHub at runtime.",
        "Upstream currency beyond the loaded release is unknown without an external check against attack-stix-data.",
        "local_file_modified_at reflects local disk write time, not upstream source publication time.",
    ]

    if not exists:
        return {
            "loaded_version": None,
            "stix_spec_version": "2.1",
            "source_url": None,
            "source_index_url": _SOURCE_INDEX_URL,
            "source_repository": _SOURCE_REPOSITORY_URL,
            "source_release_date": None,
            "source_release_date_known": False,
            "local_file_modified_at": None,
            "loaded_in_memory": domain in _loaded_domains,
            "loaded_at": _loaded_at.get(domain),
            "freshness_status": "missing_local_bundle",
            "limitations": limitations,
        }

    ver = str(version) if version is not None else str(release_info.LATEST_VERSION)
    source_release_date = _KNOWN_SOURCE_RELEASE_DATES.get(ver)
    local_file_modified_at = datetime.fromtimestamp(
        stix_path.stat().st_mtime, tz=timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "loaded_version": ver,
        "stix_spec_version": "2.1",
        "source_url": f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{domain}-attack/{domain}-attack-{ver}.json",
        "source_index_url": _SOURCE_INDEX_URL,
        "source_repository": _SOURCE_REPOSITORY_URL,
        "source_release_date": source_release_date,
        "source_release_date_known": source_release_date is not None,
        "local_file_modified_at": local_file_modified_at,
        "loaded_in_memory": domain in _loaded_domains,
        "loaded_at": _loaded_at.get(domain),
        "freshness_status": "pinned_local_release_upstream_unchecked",
        "limitations": limitations,
    }


def _compute_data_stats() -> Dict[str, Any]:
    """Internal helper: compute statistics and provenance about downloaded data."""
    stats: Dict[str, Any] = {}

    for domain in DOMAINS:
        stix_path = get_stix_path(domain)

        if stix_path.exists():
            file_size_mb = stix_path.stat().st_size / (1024 * 1024)
            provenance = _build_domain_provenance(
                domain,
                version=str(release_info.LATEST_VERSION),
                stix_path=stix_path,
                exists=True,
            )
            stats[domain] = {
                "exists": True,
                "path": f"v{release_info.LATEST_VERSION}/{stix_path.name}",
                "filename": stix_path.name,
                "size_mb": round(file_size_mb, 2),
                "version": release_info.LATEST_VERSION,
                **provenance,
            }
        else:
            provenance = _build_domain_provenance(
                domain,
                version=None,
                stix_path=stix_path,
                exists=False,
            )
            stats[domain] = {
                "exists": False,
                "path": None,
                "filename": None,
                "size_mb": 0.0,
                "version": None,
                **provenance,
            }

    return stats

def _unwrap_stix_object(item: Any) -> Any:
    """Unwrap MitreAttackData {"object": obj, ...} wrapper if present."""
    if isinstance(item, dict) and "object" in item and item["object"] is not None:
        return item["object"]
    return item


def _stix_get(obj: Any, attr: str, default: Any = None) -> Any:
    """Safely read a field from either a STIX object or a plain dict."""
    obj = _unwrap_stix_object(obj)
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(attr, default)
    return getattr(obj, attr, default)


def _get_aliases(obj: Any) -> List[str]:
    """Extract aliases from a STIX object (supporting both aliases and x_mitre_aliases)."""
    aliases = _stix_get(obj, "aliases") or _stix_get(obj, "x_mitre_aliases") or []
    return list(aliases) if aliases else []


def _extract_mitre_url(obj: Any) -> Optional[str]:
    """Extract the primary MITRE ATT&CK external reference URL from a STIX object."""
    refs = _stix_get(obj, "external_references") or []
    for ref in refs:
        src = ref.get("source_name") if isinstance(ref, dict) else getattr(ref, "source_name", None)
        url = ref.get("url") if isinstance(ref, dict) else getattr(ref, "url", None)
        if src in ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack") and url:
            return url
    for ref in refs:
        url = ref.get("url") if isinstance(ref, dict) else getattr(ref, "url", None)
        if url:
            return url
    return None


def _extract_tactic_names(obj: Any) -> List[str]:
    """Extract human-readable tactic names from a technique's kill_chain_phases."""
    phases = _stix_get(obj, "kill_chain_phases") or []
    tactics: List[str] = []
    for p in phases:
        phase_name = p.get("phase_name") if isinstance(p, dict) else getattr(p, "phase_name", None)
        if phase_name:
            tactics.append(phase_name.replace("-", " ").title())
    return tactics


_ALL_RESOLVABLE_STIX_TYPES: Tuple[str, ...] = (
    "attack-pattern",
    "intrusion-set",
    "malware",
    "tool",
    "course-of-action",
    "campaign",
    "x-mitre-data-component",
    "x-mitre-data-source",
    "x-mitre-asset",
    "x-mitre-tactic",
    "x-mitre-matrix",
    "x-mitre-detection-strategy",
    "x-mitre-analytic",
)


def _infer_stix_types_from_attack_id(raw: str) -> Tuple[str, ...]:
    """Infer candidate STIX types from an ATT&CK external ID prefix."""
    import re

    upper = raw.upper()
    lower = raw.lower()
    if re.match(r"^T\d+(?:\.\d+)?$", upper):
        return ("attack-pattern",)
    if re.match(r"^TA\d+$", upper):
        return ("x-mitre-tactic",)
    if re.match(r"^G\d+$", upper):
        return ("intrusion-set",)
    if re.match(r"^S\d+$", upper):
        return ("malware", "tool")
    if re.match(r"^M\d+$", upper):
        return ("course-of-action",)
    if re.match(r"^C\d+$", upper):
        return ("campaign",)
    if re.match(r"^(?:DC|D)\d+$", upper):
        return ("x-mitre-data-component",)
    if re.match(r"^DS\d+$", upper):
        return ("x-mitre-data-source",)
    if re.match(r"^A\d+$", upper):
        return ("x-mitre-asset",)
    if re.match(r"^DET\d+$", upper):
        return ("x-mitre-detection-strategy",)
    if re.match(r"^AN\d+$", upper):
        return ("x-mitre-analytic",)
    if lower in (
        "enterprise",
        "mobile",
        "ics",
        "enterprise-attack",
        "mobile-attack",
        "ics-attack",
    ) or "att&ck" in lower:
        return ("x-mitre-matrix",)
    return _ALL_RESOLVABLE_STIX_TYPES


def _resolve_stix_object(
    identifier: str,
    domain: str = "enterprise",
    expected_stix_type: Optional[Any] = None,
) -> Tuple[Optional[str], Optional[Any], Optional[str]]:
    """Resolve either a STIX ID or an ATT&CK ID to (stix_id, stix_obj, error_message).

    Accepts STIX UUIDs (e.g., 'attack-pattern--...', 'intrusion-set--...') as well as
    ATT&CK external IDs (e.g., 'T1190', 'T1566.002', 'G0016', 'S0154', 'M1051',
    'C0024', 'DC0032', 'A0003', 'enterprise-attack').
    """
    raw = (identifier or "").strip()
    dom = (domain or "enterprise").strip().lower()
    if not raw:
        return None, None, f"Empty identifier provided for domain '{dom}'."

    expected_types: Optional[Tuple[str, ...]] = None
    if isinstance(expected_stix_type, str) and expected_stix_type.strip():
        expected_types = (expected_stix_type.strip().lower(),)
    elif isinstance(expected_stix_type, (tuple, list, set)):
        cleaned = tuple(str(t).strip().lower() for t in expected_stix_type if str(t).strip())
        if cleaned:
            expected_types = cleaned

    ad = get_attack_data(dom)

    # 1. STIX ID path (contains "--")
    if "--" in raw:
        obj = None
        for candidate in (raw, raw.lower()):
            try:
                obj = ad.get_object_by_stix_id(candidate)
            except Exception:
                obj = None
            if obj is not None:
                break
        if obj is None:
            return None, None, f"STIX ID '{raw}' was not found in domain '{dom}'."
        obj = _unwrap_stix_object(obj)
        resolved_id = _stix_get(obj, "id") or raw.lower()
        actual_type = (_stix_get(obj, "type") or "").lower()
        if expected_types and actual_type and actual_type not in expected_types:
            return (
                None,
                None,
                f"Identifier '{raw}' resolved to STIX type '{actual_type}', "
                f"expected {', '.join(expected_types)} in domain '{dom}'.",
            )
        return resolved_id, obj, None

    # 2. ATT&CK ID / matrix name path
    candidate_types = expected_types or _infer_stix_types_from_attack_id(raw)
    raw_upper = raw.upper()
    raw_lower = raw.lower()

    # Special matrix resolution (e.g., 'enterprise-attack', 'enterprise', 'Enterprise ATT&CK')
    if "x-mitre-matrix" in candidate_types:
        try:
            matrices = ad.get_matrices(remove_revoked_deprecated=False) or []
        except Exception:
            matrices = []
        for m in matrices:
            m_obj = _unwrap_stix_object(m)
            m_id = _stix_get(m_obj, "id")
            m_name = (_stix_get(m_obj, "name") or "").strip().lower()
            try:
                m_aid = (ad.get_attack_id(m_id) or "").strip().lower() if m_id else ""
            except Exception:
                m_aid = ""
            if raw_lower in {m_aid, m_name, m_aid.removesuffix("-attack")} and m_id:
                return m_id, m_obj, None

    # Standard ATT&CK ID lookup via MitreAttackData
    for stix_type in candidate_types:
        for candidate_id in (raw_upper, raw):
            try:
                obj = ad.get_object_by_attack_id(candidate_id, stix_type)
            except Exception:
                obj = None
            if obj is not None:
                obj = _unwrap_stix_object(obj)
                resolved_id = _stix_get(obj, "id")
                if resolved_id:
                    return resolved_id, obj, None

    # Fallback scan over external_references for types not indexed by get_object_by_attack_id
    for stix_type in candidate_types:
        try:
            objs = ad.get_objects_by_type(stix_type, remove_revoked_deprecated=False) or []
        except Exception:
            objs = []
        for item in objs:
            obj = _unwrap_stix_object(item)
            refs = _stix_get(obj, "external_references") or []
            for ref in refs:
                ext_id = (
                    ref.get("external_id")
                    if isinstance(ref, dict)
                    else getattr(ref, "external_id", None)
                )
                if ext_id and str(ext_id).strip().lower() == raw_lower:
                    resolved_id = _stix_get(obj, "id")
                    if resolved_id:
                        return resolved_id, obj, None

    expected_desc = (
        "/".join(expected_types) if expected_types else "ATT&CK object"
    )
    return (
        None,
        None,
        f"Identifier '{raw}' could not be resolved to a valid {expected_desc} in domain '{dom}'.",
    )


def resolve_stix_id(
    identifier: str,
    domain: str = "enterprise",
    expected_stix_type: Optional[Any] = None,
) -> Optional[str]:
    """Resolve a STIX ID or ATT&CK ID to its canonical STIX ID, or None if unresolvable."""
    stix_id, _, _ = _resolve_stix_object(
        identifier, domain=domain, expected_stix_type=expected_stix_type
    )
    return stix_id


def _normalize_tactic_shortname(attack_data: Any, tactic: str) -> str:
    """Resolve a tactic name, ATT&CK ID, or shortname to its x_mitre_shortname."""
    raw = (tactic or "").strip()
    norm = raw.lower()
    try:
        tactics = attack_data.get_tactics(remove_revoked_deprecated=True) or []
    except Exception:
        tactics = []
    for t in tactics:
        t_name = (_stix_get(t, "name", "") or "").strip()
        t_short = (_stix_get(t, "x_mitre_shortname", "") or "").strip()
        t_id = _stix_get(t, "id")
        t_attack_id = None
        if t_id:
            try:
                t_attack_id = attack_data.get_attack_id(t_id)
            except Exception:
                t_attack_id = None
        if norm in {
            t_name.lower(),
            t_short.lower(),
            (t_attack_id or "").lower(),
            t_name.lower().replace(" ", "-"),
        }:
            if t_short:
                return t_short
    return norm.replace(" ", "-")


_LEGACY_TACTIC_MIGRATIONS: Dict[str, Dict[str, Any]] = {
    "defense evasion": {
        "suggested_tactics": ["Stealth", "Defense Impairment"],
        "hint": (
            "In ATT&CK v20.1, 'Defense Evasion' was reorganized into "
            "'Stealth' and 'Defense Impairment'. Try querying those tactics."
        ),
    },
    "defense-evasion": {
        "suggested_tactics": ["Stealth", "Defense Impairment"],
        "hint": (
            "In ATT&CK v20.1, 'Defense Evasion' was reorganized into "
            "'Stealth' and 'Defense Impairment'. Try querying those tactics."
        ),
    },
}

_REAL_WORLD_PLATFORM_HINTS: Dict[str, List[str]] = {
    # NAS & storage appliances
    "nas": ["Linux", "Network Devices"],
    "qnap": ["Linux", "Network Devices"],
    "synology": ["Linux", "Network Devices"],
    "truenas": ["Linux", "Network Devices"],
    "freenas": ["Linux", "Network Devices"],
    "qts": ["Linux", "Network Devices"],
    "dsm": ["Linux", "Network Devices"],
    # Network devices, routers, Wi-Fi, firewalls
    "router": ["Network Devices"],
    "wi-fi": ["Network Devices"],
    "wifi": ["Network Devices"],
    "wireless": ["Network Devices"],
    "access point": ["Network Devices"],
    "firewall": ["Network Devices"],
    "switch": ["Network Devices"],
    "vpn": ["Network Devices"],
    "gateway": ["Network Devices"],
    "modem": ["Network Devices"],
    "cisco": ["Network Devices"],
    "juniper": ["Network Devices"],
    "fortinet": ["Network Devices"],
    "fortigate": ["Network Devices"],
    "palo alto": ["Network Devices"],
    "mikrotik": ["Network Devices"],
    "openwrt": ["Network Devices"],
    "dd-wrt": ["Network Devices"],
    "ubiquiti": ["Network Devices"],
    # Linux distributions
    "ubuntu": ["Linux"],
    "debian": ["Linux"],
    "rhel": ["Linux"],
    "red hat": ["Linux"],
    "redhat": ["Linux"],
    "centos": ["Linux"],
    "rocky": ["Linux"],
    "almalinux": ["Linux"],
    "fedora": ["Linux"],
    "suse": ["Linux"],
    "opensuse": ["Linux"],
    "alpine": ["Linux"],
    "kali": ["Linux"],
    "linux server": ["Linux"],
    "ubuntu server": ["Linux"],
    # Windows variants
    "windows 10": ["Windows"],
    "windows 11": ["Windows"],
    "win10": ["Windows"],
    "win11": ["Windows"],
    "windows server": ["Windows"],
    "active directory": ["Windows"],
    # macOS variants
    "osx": ["macOS"],
    "os x": ["macOS"],
    "macbook": ["macOS"],
    # Containers & orchestration
    "docker": ["Containers"],
    "kubernetes": ["Containers"],
    "k8s": ["Containers"],
    "container": ["Containers"],
    "podman": ["Containers"],
    "openshift": ["Containers"],
    # Cloud providers
    "aws": ["IaaS", "SaaS", "Identity Provider"],
    "amazon web services": ["IaaS", "SaaS", "Identity Provider"],
    "azure": ["IaaS", "SaaS", "Identity Provider"],
    "microsoft azure": ["IaaS", "SaaS", "Identity Provider"],
    "gcp": ["IaaS", "SaaS", "Identity Provider"],
    "google cloud": ["IaaS", "SaaS", "Identity Provider"],
    "google cloud platform": ["IaaS", "SaaS", "Identity Provider"],
    "oci": ["IaaS", "SaaS", "Identity Provider"],
    "oracle cloud": ["IaaS", "SaaS", "Identity Provider"],
    "cloud": ["IaaS", "SaaS", "Identity Provider"],
    # Virtualization / hypervisors
    "vmware": ["ESXi"],
    "vsphere": ["ESXi"],
    "vcenter": ["ESXi"],
    "hypervisor": ["ESXi"],
    # Identity / SaaS / Office suites
    "okta": ["Identity Provider", "SaaS"],
    "entra": ["Identity Provider", "SaaS"],
    "entra id": ["Identity Provider", "SaaS"],
    "m365": ["Office Suite", "SaaS", "Identity Provider"],
    "microsoft 365": ["Office Suite", "SaaS", "Identity Provider"],
    "o365": ["Office Suite", "SaaS", "Identity Provider"],
}


def _suggest_attack_platforms(
    raw_platform: str,
    available_platforms: List[str],
) -> List[str]:
    """Map real-world IT asset labels (e.g. 'QNAP', 'Ubuntu', 'Wi-Fi', 'AWS')
    to valid ATT&CK platform names available in the requested domain.
    """
    norm = " ".join((raw_platform or "").strip().lower().split())
    if not norm or not available_platforms:
        return []

    avail_by_lower = {p.lower(): p for p in available_platforms}
    candidates: List[str] = []

    if norm in _REAL_WORLD_PLATFORM_HINTS:
        candidates.extend(_REAL_WORLD_PLATFORM_HINTS[norm])
    else:
        for term, plats in _REAL_WORLD_PLATFORM_HINTS.items():
            if re.search(r"(?<!\w)" + re.escape(term) + r"(?!\w)", norm):
                candidates.extend(plats)

    suggested: List[str] = []
    seen: set[str] = set()
    for plat in candidates:
        canon = avail_by_lower.get(plat.lower())
        if canon and canon not in seen:
            seen.add(canon)
            suggested.append(canon)
    return suggested


def _extract_available_platforms(objects: List[Any]) -> List[str]:
    """Extract sorted unique canonical platform names from STIX objects with x_mitre_platforms."""
    known: Dict[str, str] = {}
    for obj in objects or []:
        for p in (_stix_get(obj, "x_mitre_platforms") or []):
            if p and str(p).strip():
                ps = str(p).strip()
                known[ps.lower()] = ps
    return sorted(set(known.values()))


def _suggest_attack_platforms_for_list(
    raw_platforms: Optional[List[str]],
    available_platforms: List[str],
) -> List[str]:
    """Collect deduplicated ATT&CK platform suggestions for a list of requested platform labels."""
    if not raw_platforms or not available_platforms:
        return []
    avail_lower = {p.lower() for p in available_platforms}
    suggested: List[str] = []
    seen: set[str] = set()
    for raw_plat in raw_platforms:
        if not raw_plat or not str(raw_plat).strip():
            continue
        if str(raw_plat).strip().lower() in avail_lower:
            continue
        for cand in _suggest_attack_platforms(str(raw_plat), available_platforms):
            if cand not in seen:
                seen.add(cand)
                suggested.append(cand)
    return suggested


def _normalize_technique_platforms(
    platforms: Optional[List[str]],
    techniques: Optional[List[Any]] = None,
) -> Optional[List[str]]:
    """Normalize an optional list of platform filter names for technique queries.

    Returns None when no non-empty platform filter is requested (preserving
    unfiltered backward-compatible behavior). When provided, resolves canonical
    platform casing from known techniques when available and returns a
    deduplicated, deterministically sorted list.
    """
    if platforms is None:
        return None
    raw_items = [str(p).strip() for p in platforms if p is not None and str(p).strip()]
    if not raw_items:
        return None

    known_lower: Dict[str, str] = {}
    if techniques:
        for tech in techniques:
            for p in (_stix_get(tech, "x_mitre_platforms") or []):
                if p and str(p).strip():
                    ps = str(p).strip()
                    known_lower[ps.lower()] = ps

    dedup: Dict[str, str] = {}
    for item in raw_items:
        key = item.lower()
        if key not in dedup:
            dedup[key] = known_lower.get(key, item)
    return sorted(dedup.values())


def _technique_matches_platforms(tech: Any, platform_set_lower: set[str]) -> bool:
    """Return True if technique applies to at least one platform in platform_set_lower."""
    tech_platforms = _stix_get(tech, "x_mitre_platforms", []) or []
    return any(
        str(p).strip().lower() in platform_set_lower
        for p in tech_platforms
        if p is not None and str(p).strip()
    )


def _extract_dc_log_sources(dc: Any) -> List[Dict[str, str]]:
    """Extract normalized ATT&CK v20.1 `x_mitre_log_sources` entries from a data component."""
    raw = _stix_get(dc, "x_mitre_log_sources") or _stix_get(dc, "x-mitre-log-sources") or []
    result: List[Dict[str, str]] = []
    if not isinstance(raw, (list, tuple)):
        return result
    for entry in raw:
        if isinstance(entry, dict):
            ls_name = entry.get("name")
            ls_channel = entry.get("channel")
        else:
            ls_name = getattr(entry, "name", None)
            ls_channel = getattr(entry, "channel", None)
        name_str = str(ls_name) if ls_name is not None else ""
        channel_str = str(ls_channel) if ls_channel is not None else ""
        if name_str or channel_str:
            result.append({"name": name_str, "channel": channel_str})
    return result

_V20_DETECTION_CACHE: Dict[str, Dict[str, Any]] = {}
_V20_MITIGATION_CACHE: Dict[str, Dict[str, Any]] = {}


def _get_v20_mitigation_index(domain: str) -> Dict[str, Any]:
    """Build and cache ATT&CK mitigation graph:
    technique <-> course-of-action (mitigates relationship).
    """
    dom = (domain or "enterprise").strip().lower()
    if dom in _V20_MITIGATION_CACHE:
        return _V20_MITIGATION_CACHE[dom]

    ad = get_attack_data(dom)
    try:
        mitigations = ad.get_mitigations(remove_revoked_deprecated=True) or []
    except Exception:
        mitigations = []
    try:
        relationships = ad.get_objects_by_type("relationship", remove_revoked_deprecated=True) or []
    except Exception:
        relationships = []
    try:
        all_techniques = ad.get_techniques(remove_revoked_deprecated=False) or []
    except Exception:
        all_techniques = []

    tech_by_stix_id: Dict[str, Any] = {}
    tech_by_attack_id: Dict[str, Any] = {}
    tech_attack_id_by_id: Dict[str, Optional[str]] = {}
    for tech in all_techniques:
        t_obj = _unwrap_stix_object(tech)
        t_id = _stix_get(t_obj, "id")
        if not t_id:
            continue
        t_id_lower = str(t_id).lower()
        tech_by_stix_id[t_id_lower] = t_obj
        t_aid: Optional[str] = None
        for ref in (_stix_get(t_obj, "external_references") or []):
            src_name = ref.get("source_name") if isinstance(ref, dict) else getattr(ref, "source_name", None)
            ext_id = ref.get("external_id") if isinstance(ref, dict) else getattr(ref, "external_id", None)
            if ext_id and src_name in ("mitre-attack", "mitre-ics-attack", "mitre-mobile-attack"):
                t_aid = str(ext_id).strip().upper()
                break
        if t_aid is None:
            for ref in (_stix_get(t_obj, "external_references") or []):
                ext_id = ref.get("external_id") if isinstance(ref, dict) else getattr(ref, "external_id", None)
                if ext_id and _TECHNIQUE_ATTACK_ID_RE.match(str(ext_id).strip()):
                    t_aid = str(ext_id).strip().upper()
                    break
        tech_attack_id_by_id[t_id] = t_aid
        if t_aid:
            existing = tech_by_attack_id.get(t_aid)
            if existing is None or (
                (_stix_get(existing, "revoked", False) or _stix_get(existing, "x_mitre_deprecated", False))
                and not (_stix_get(t_obj, "revoked", False) or _stix_get(t_obj, "x_mitre_deprecated", False))
            ):
                tech_by_attack_id[t_aid] = t_obj

    mit_by_id: Dict[str, Any] = {}
    mit_attack_id_by_id: Dict[str, Optional[str]] = {}
    for m in mitigations:
        m_obj = _unwrap_stix_object(m)
        m_id = _stix_get(m_obj, "id")
        if not m_id:
            continue
        mit_by_id[m_id] = m_obj
        try:
            mit_attack_id_by_id[m_id] = ad.get_attack_id(m_id)
        except Exception:
            mit_attack_id_by_id[m_id] = None

    tech_to_mits: Dict[str, List[str]] = {}
    for rel in relationships:
        if _stix_get(rel, "relationship_type") != "mitigates":
            continue
        src = _stix_get(rel, "source_ref")
        tgt = _stix_get(rel, "target_ref")
        if src in mit_by_id and tgt:
            mlist = tech_to_mits.setdefault(tgt, [])
            if src not in mlist:
                mlist.append(src)

    index = {
        "tech_by_stix_id": tech_by_stix_id,
        "tech_by_attack_id": tech_by_attack_id,
        "tech_attack_id_by_id": tech_attack_id_by_id,
        "mit_by_id": mit_by_id,
        "mit_attack_id_by_id": mit_attack_id_by_id,
        "tech_to_mits": tech_to_mits,
    }
    _V20_MITIGATION_CACHE[dom] = index
    return index


def _get_v20_detection_index(domain: str) -> Dict[str, Any]:
    """Build and cache ATT&CK v20.1 detection graph:
    technique <-> detection-strategy <-> analytic <-> data-component.
    """
    dom = (domain or "enterprise").strip().lower()
    if dom in _V20_DETECTION_CACHE:
        return _V20_DETECTION_CACHE[dom]

    ad = get_attack_data(dom)
    try:
        det_strategies = ad.get_objects_by_type("x-mitre-detection-strategy", remove_revoked_deprecated=True) or []
    except Exception:
        det_strategies = []
    try:
        analytics = ad.get_objects_by_type("x-mitre-analytic", remove_revoked_deprecated=True) or []
    except Exception:
        analytics = []
    try:
        datacomponents = ad.get_datacomponents(remove_revoked_deprecated=True) or []
    except Exception:
        datacomponents = []
    try:
        relationships = ad.get_objects_by_type("relationship", remove_revoked_deprecated=True) or []
    except Exception:
        relationships = []
    try:
        all_techniques = ad.get_techniques(remove_revoked_deprecated=False) or []
    except Exception:
        all_techniques = []

    tech_by_stix_id: Dict[str, Any] = {}
    tech_by_attack_id: Dict[str, Any] = {}
    tech_attack_id_by_id: Dict[str, Optional[str]] = {}
    for tech in all_techniques:
        t_obj = _unwrap_stix_object(tech)
        t_id = _stix_get(t_obj, "id")
        if not t_id:
            continue
        t_id_lower = str(t_id).lower()
        tech_by_stix_id[t_id_lower] = t_obj
        t_aid: Optional[str] = None
        for ref in (_stix_get(t_obj, "external_references") or []):
            src_name = ref.get("source_name") if isinstance(ref, dict) else getattr(ref, "source_name", None)
            ext_id = ref.get("external_id") if isinstance(ref, dict) else getattr(ref, "external_id", None)
            if ext_id and src_name in ("mitre-attack", "mitre-ics-attack", "mitre-mobile-attack"):
                t_aid = str(ext_id).strip().upper()
                break
        if t_aid is None:
            for ref in (_stix_get(t_obj, "external_references") or []):
                ext_id = ref.get("external_id") if isinstance(ref, dict) else getattr(ref, "external_id", None)
                if ext_id and _TECHNIQUE_ATTACK_ID_RE.match(str(ext_id).strip()):
                    t_aid = str(ext_id).strip().upper()
                    break
        tech_attack_id_by_id[t_id] = t_aid
        if t_aid:
            # Prefer non-revoked/non-deprecated object if duplicate external_id exists
            existing = tech_by_attack_id.get(t_aid)
            if existing is None or (
                (_stix_get(existing, "revoked", False) or _stix_get(existing, "x_mitre_deprecated", False))
                and not (_stix_get(t_obj, "revoked", False) or _stix_get(t_obj, "x_mitre_deprecated", False))
            ):
                tech_by_attack_id[t_aid] = t_obj

    ds_by_id = {_stix_get(d, "id"): d for d in det_strategies if _stix_get(d, "id")}
    an_by_id = {_stix_get(a, "id"): a for a in analytics if _stix_get(a, "id")}
    dc_by_id = {_stix_get(c, "id"): c for c in datacomponents if _stix_get(c, "id")}
    ds_attack_id_by_id: Dict[str, Optional[str]] = {}
    for ds_id in ds_by_id:
        try:
            ds_attack_id_by_id[ds_id] = ad.get_attack_id(ds_id)
        except Exception:
            ds_attack_id_by_id[ds_id] = None
    an_attack_id_by_id: Dict[str, Optional[str]] = {}
    for an_id in an_by_id:
        try:
            an_attack_id_by_id[an_id] = ad.get_attack_id(an_id)
        except Exception:
            an_attack_id_by_id[an_id] = None
    dc_attack_id_by_id: Dict[str, Optional[str]] = {}
    for dc_id in dc_by_id:
        try:
            dc_attack_id_by_id[dc_id] = ad.get_attack_id(dc_id)
        except Exception:
            dc_attack_id_by_id[dc_id] = None

    # Map detection strategy -> techniques and technique -> detection strategies
    tech_to_ds: Dict[str, List[str]] = {}
    ds_to_tech: Dict[str, List[str]] = {}
    for rel in relationships:
        if _stix_get(rel, "relationship_type") != "detects":
            continue
        src = _stix_get(rel, "source_ref")
        tgt = _stix_get(rel, "target_ref")
        if src in ds_by_id and tgt:
            tech_to_ds.setdefault(tgt, []).append(src)
            ds_to_tech.setdefault(src, []).append(tgt)

    # Map analytic -> data components and normalized log source references
    an_to_dcs: Dict[str, List[str]] = {}
    an_log_source_refs: Dict[str, List[Dict[str, Optional[str]]]] = {}
    for an_id, an_obj in an_by_id.items():
        log_refs = _stix_get(an_obj, "x_mitre_log_source_references") or []
        dc_ids: List[str] = []
        norm_refs: List[Dict[str, Optional[str]]] = []
        for lr in log_refs:
            dc_ref = (
                lr.get("x_mitre_data_component_ref")
                if isinstance(lr, dict)
                else getattr(lr, "x_mitre_data_component_ref", None)
            )
            lr_name = (
                lr.get("name")
                if isinstance(lr, dict)
                else getattr(lr, "name", None)
            )
            lr_channel = (
                lr.get("channel")
                if isinstance(lr, dict)
                else getattr(lr, "channel", None)
            )
            if dc_ref and dc_ref not in dc_ids:
                dc_ids.append(dc_ref)
            if dc_ref or lr_name or lr_channel:
                norm_refs.append({
                    "data_component_stix_id": dc_ref,
                    "name": str(lr_name).strip() if lr_name else None,
                    "channel": str(lr_channel).strip() if lr_channel else None,
                })
        an_to_dcs[an_id] = dc_ids
        an_log_source_refs[an_id] = norm_refs

    # Build technique -> data components and data component -> techniques
    tech_to_dcs: Dict[str, List[str]] = {}
    dc_to_techs: Dict[str, List[str]] = {}
    for tech_id, ds_ids in tech_to_ds.items():
        seen_dc: List[str] = []
        for ds_id in ds_ids:
            ds_obj = ds_by_id.get(ds_id)
            for an_id in (_stix_get(ds_obj, "x_mitre_analytic_refs") or []):
                for dc_id in an_to_dcs.get(an_id, []):
                    if dc_id not in seen_dc:
                        seen_dc.append(dc_id)
                    tlist = dc_to_techs.setdefault(dc_id, [])
                    if tech_id not in tlist:
                        tlist.append(tech_id)
        tech_to_dcs[tech_id] = seen_dc

    index = {
        "tech_by_stix_id": tech_by_stix_id,
        "tech_by_attack_id": tech_by_attack_id,
        "tech_attack_id_by_id": tech_attack_id_by_id,
        "ds_by_id": ds_by_id,
        "ds_attack_id_by_id": ds_attack_id_by_id,
        "an_by_id": an_by_id,
        "an_attack_id_by_id": an_attack_id_by_id,
        "dc_by_id": dc_by_id,
        "dc_attack_id_by_id": dc_attack_id_by_id,
        "tech_to_ds": tech_to_ds,
        "ds_to_tech": ds_to_tech,
        "an_to_dcs": an_to_dcs,
        "an_log_source_refs": an_log_source_refs,
        "tech_to_dcs": tech_to_dcs,
        "dc_to_techs": dc_to_techs,
    }
    _V20_DETECTION_CACHE[dom] = index
    return index


def _resolve_revoked_by(attack_data: Any, stix_id: Optional[str]) -> Optional[Dict[str, Any]]:
    if not stix_id:
        return None
    try:
        rev_obj = attack_data.get_revoking_object(stix_id)
    except Exception:
        rev_obj = None
    if rev_obj is None:
        return None
    rev_stix_id = _stix_get(rev_obj, "id")
    try:
        rev_attack_id = attack_data.get_attack_id(rev_stix_id) if rev_stix_id else None
    except Exception:
        rev_attack_id = None
    return {
        "attack_id": rev_attack_id,
        "name": _stix_get(rev_obj, "name"),
        "stix_id": rev_stix_id,
    }


def format_objects(
    objects: List[Any],
    include_description: bool = False,
    domain: str = "enterprise"
) -> str:
    """
    Format a list of MITRE ATT&CK objects into a clean, readable string.

    Args:
        objects: List of STIX objects or dicts containing {"object": obj}.
        include_description: Whether to include object descriptions.
        domain: ATT&CK domain ("enterprise", "mobile", "ics").

    Returns:
        A formatted multi-line string.
    """
    attack_data = get_attack_data(domain)
    formatted = []

    for obj in objects:
        obj = _unwrap_stix_object(obj)
        if obj is None:
            continue

        lines = []

        # Name --------------------------------------------------------------
        name = _stix_get(obj, "name")
        if name:
            lines.append(f"Name: {name}")

        # STIX ID -----------------------------------------------------------
        stix_id = _stix_get(obj, "id")

        # External ATT&CK ID (e.g., T1059, G0032) ---------------------------
        try:
            external_id = attack_data.get_attack_id(stix_id or obj)
            if external_id:
                lines.append(f"ID: {external_id}")
        except Exception:
            pass  # not all objects map cleanly

        if stix_id:
            lines.append(f"STIX ID: {stix_id}")

        # Source reference (relationships only) -----------------------------
        source_ref = _stix_get(obj, "source_ref")
        if source_ref:
            lines.append(f"Source Reference: {source_ref}")

        # Aliases -----------------------------------------------------------
        aliases = _stix_get(obj, "aliases") or _stix_get(obj, "x_mitre_aliases")
        if aliases:
            lines.append(f"Aliases: {aliases}")

        # Description -------------------------------------------------------
        description = _stix_get(obj, "description")
        if include_description and description:
            lines.append(f"Description: {description}")

        formatted.append("\n".join(lines))

    return "\n---\n".join(formatted)


# ---------------------------------------------------------------------------
# MCP server & first tool
# ---------------------------------------------------------------------------

mcp = FastMCP("mitre-attack-mcp-server")

READ_ONLY_LOCAL_ANNOTATIONS = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)


def _resolve_local_version(base_version: str = "0.1.6") -> str:
    """Append +local.<short-sha>[.dirty] SemVer build metadata from git."""
    import subprocess

    repo_dir = Path(__file__).resolve().parents[2]
    try:
        sha = subprocess.check_output(
            ["git", "-C", str(repo_dir), "rev-parse", "--short", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        if not sha:
            return base_version
        dirty = subprocess.check_output(
            ["git", "-C", str(repo_dir), "status", "--porcelain"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        suffix = f"+local.{sha}.dirty" if dirty else f"+local.{sha}"
        return f"{base_version}{suffix}"
    except Exception:
        return base_version


SERVER_VERSION = _resolve_local_version("0.1.6")
mcp._mcp_server.version = SERVER_VERSION


@mcp.custom_route("/healthz", methods=["GET"])
async def healthz_route(request):
    from starlette.responses import JSONResponse

    return JSONResponse(
        {"status": "ok", "service": "mitre-attack-mcp-server", "version": SERVER_VERSION}
    )


@mcp.custom_route("/mcp", methods=["HEAD"])
async def mcp_head_route(request):
    from starlette.responses import Response

    return Response(status_code=200, headers={"Content-Type": "application/json"})


@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_data_stats() -> Dict[str, Any]:
    """
    Return statistics about downloaded MITRE ATT&CK STIX data.

    This confirms which domains are present on disk, their file paths,
    sizes, and ATT&CK release version. It assumes that downloads have
    already been attempted at server startup.
    """
    return _compute_data_stats()

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_technique_by_id(
    technique_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
    include_formatted: bool = True,
    ) -> Dict[str, Any]:
    """
    Retrieve a MITRE ATT&CK technique by its external ATT&CK ID (e.g., "T1055", "T1053.005").

    This tool searches the specified ATT&CK domain (enterprise, mobile, or ics)
    and returns both structured machine-readable data and an optional formatted
    human-readable text block. It is useful for user-facing responses as well
    as downstream programmatic reasoning.

    Args:
        technique_id: The external ATT&CK technique ID (e.g., "T1055").
        domain: ATT&CK domain to search in ("enterprise", "mobile", "ics").
        include_description: If True, returns the full ATT&CK description text.
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
          "found": bool,
          "technique": {
              "id": "<ATT&CK ID>",
              "name": "<technique name>",
              "stix_id": "<STIX object ID>",
              "platforms": [...],
              "tactics": [...],
              "is_subtechnique": bool,
              "mitre_url": "<URL or null>",
              "modified": "<ISO8601 timestamp or null>",
              "revoked": bool,
              "deprecated": bool,
              "revoked_by": {...} | null,
              "description": "<full description or null>"
          },
          "formatted": "<human-readable formatted block>",
          "message": "<status message>"
        }
    """

    attack_data = get_attack_data(domain)
    norm_id = (technique_id or "").strip().upper()

    # Library already supports this lookup!
    tech = attack_data.get_object_by_attack_id(
        norm_id,
        "attack-pattern"
    )

    if tech is None:
        return {
            "found": False,
            "message": f"Technique '{norm_id}' not found in domain '{domain}'."
        }

    stix_id = _stix_get(tech, "id")
    is_revoked = bool(_stix_get(tech, "revoked", False))
    is_deprecated = bool(_stix_get(tech, "x_mitre_deprecated", False))
    revoked_by = _resolve_revoked_by(attack_data, stix_id) if is_revoked else None
    platforms = list(_stix_get(tech, "x_mitre_platforms") or [])
    tactics = _extract_tactic_names(tech)
    is_subtechnique = bool(_stix_get(tech, "x_mitre_is_subtechnique", False))
    mitre_url = _extract_mitre_url(tech)
    modified_val = _stix_get(tech, "modified")
    modified = str(modified_val) if modified_val is not None else None

    formatted = (
        format_objects(
            [tech],
            include_description=include_description,
            domain=domain,
        )
        if include_formatted
        else ""
    )

    msg = f"Found technique '{norm_id}' ({_stix_get(tech, 'name')}) in domain '{domain}'."
    if is_revoked:
        if revoked_by and revoked_by.get("attack_id"):
            msg += f" WARNING: This technique is REVOKED and superseded by {revoked_by['attack_id']} ({revoked_by.get('name')})."
        else:
            msg += " WARNING: This technique is REVOKED."
    elif is_deprecated:
        msg += " WARNING: This technique is DEPRECATED."

    return {
        "found": True,
        "technique": {
            "id": norm_id,
            "name": _stix_get(tech, "name"),
            "stix_id": stix_id,
            "platforms": platforms,
            "tactics": tactics,
            "is_subtechnique": is_subtechnique,
            "mitre_url": mitre_url,
            "modified": modified,
            "revoked": is_revoked,
            "deprecated": is_deprecated,
            "revoked_by": revoked_by,
            "description": _stix_get(tech, "description") if include_description else None,
        },
        "formatted": formatted,
        "message": msg,
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_object_by_attack_id(
    attack_id: str,
    stix_type: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Retrieve any MITRE ATT&CK object by its external ATT&CK ID and STIX type.

    This tool supports techniques, intrusion sets (APT groups), malware,
    tools, mitigations, campaigns, data sources, data components, and tactics.

    Args:
        attack_id: The external ATT&CK ID (e.g., "T1055", "G0016", "S0154", "M1013").
        stix_type: The STIX object type (e.g., "attack-pattern", "intrusion-set").
        domain: ATT&CK domain ("enterprise", "mobile", or "ics").
        include_description: Whether to include the object's description field.

    Returns:
        {
          "found": bool,
          "object": {
              "id": "<ATT&CK ID>",
              "name": "<object name>",
              "stix_id": "<STIX object ID>",
              "type": "<stix_type>",
              "description": "<description or null>"
          },
          "formatted": "<human-readable formatted output>",
          "message": "<status>"
        }
    """
    attack_data = get_attack_data(domain)
    norm_id = (attack_id or "").strip().upper()
    norm_type = (stix_type or "").strip().lower()

    try:
        obj = attack_data.get_object_by_attack_id(norm_id, norm_type)
    except Exception:
        obj = None

    if obj is None:
        return {
            "found": False,
            "object": None,
            "formatted": "",
            "message": (
                f"No object found for ATT&CK ID '{norm_id}' with STIX type "
                f"'{norm_type}' in domain '{domain}'."
            ),
        }

    # Handle object fields (works for dict and STIX object instances)
    name = getattr(obj, "name", None) if not isinstance(obj, dict) else obj.get("name")
    stix_id = getattr(obj, "id", None) if not isinstance(obj, dict) else obj.get("id")
    description = (
        getattr(obj, "description", None)
        if include_description and not isinstance(obj, dict)
        else (obj.get("description") if include_description else None)
    )
    resolved_id = norm_id
    if stix_id:
        try:
            resolved_id = attack_data.get_attack_id(stix_id) or norm_id
        except Exception:
            resolved_id = norm_id

    formatted = format_objects(
        [obj],
        include_description=include_description,
        domain=domain,
    )

    return {
        "found": True,
        "object": {
            "id": resolved_id,
            "name": name,
            "stix_id": stix_id,
            "type": norm_type,
            "description": description,
        },
        "formatted": formatted,
        "message": f"Object found for ATT&CK ID '{resolved_id}' in domain '{domain}'.",
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_object_by_stix_id(
    stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Retrieve any MITRE ATT&CK object by its STIX ID (UUID).

    STIX IDs are internal identifiers like:
      - attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b

    This tool is useful when you already have a STIX ID from another
    query or relationship and want to resolve it to the full object.

    Args:
        stix_id: STIX object ID (e.g., "attack-pattern--...").
        domain: ATT&CK domain to search in ("enterprise", "mobile", "ics").
        include_description: Whether to include the object's description.

    Returns:
        {
          "found": bool,
          "object": {
              "attack_id": "<ATT&CK external ID or null>",
              "name": "<object name>",
              "stix_id": "<STIX ID>",
              "type": "<stix type>",
              "description": "<description or null>"
          },
          "formatted": "<human-readable formatted text>",
          "message": "<status message>"
        }
    """
    attack_data = get_attack_data(domain)

    # Resolve the object by its STIX ID
    try:
        obj = attack_data.get_object_by_stix_id(stix_id)
    except Exception:
        obj = None

    if obj is None:
        return {
            "found": False,
            "object": None,
            "formatted": "",
            "message": f"No object found for STIX ID '{stix_id}' in domain '{domain}'.",
        }

    # Handle dict-like vs object-like STIX representations
    if isinstance(obj, dict):
        name = obj.get("name")
        stix_type = obj.get("type")
        raw_id = obj.get("id", stix_id)
        description = obj.get("description") if include_description else None
    else:
        name = getattr(obj, "name", None)
        stix_type = getattr(obj, "type", None)
        raw_id = getattr(obj, "id", stix_id)
        description = getattr(obj, "description", None) if include_description else None

    # Try to resolve external ATT&CK ID for this STIX object (if it has one)
    attack_id = None
    try:
        attack_id = attack_data.get_attack_id(raw_id)
    except Exception:
        pass

    formatted = format_objects(
        [obj],
        include_description=include_description,
        domain=domain,
    )

    return {
        "found": True,
        "object": {
            "attack_id": attack_id,
            "name": name,
            "stix_id": raw_id,
            "type": stix_type,
            "description": description,
        },
         "formatted": formatted,
        "message": f"Object found for STIX ID '{stix_id}' in domain '{domain}'.",
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_objects_by_name(
    name: str,
    stix_type: str,
    domain: str = "enterprise",
    include_description: bool = False,
    remove_revoked_deprecated: bool = True,
) -> Dict[str, Any]:
    """
    Retrieve MITRE ATT&CK objects by exact name match (case-insensitive).

    This tool performs an exact name match for a specific STIX type within
    a given ATT&CK domain. It is more strict than generic search methods,
    which typically perform partial or keyword matching.

    Examples:
        - Technique: get_objects_by_name("Phishing", "attack-pattern")
        - Group: get_objects_by_name("APT29", "intrusion-set")
        - Malware: get_objects_by_name("Cobalt Strike", "malware")

    Args:
        name: Exact object name to search for (case-insensitive).
        stix_type: STIX object type (same values as get_object_by_attack_id),
                   e.g. "attack-pattern", "intrusion-set", "malware",
                   "tool", "course-of-action", etc.
        domain: ATT&CK domain ("enterprise", "mobile", or "ics").
        include_description: Whether to include descriptions in the formatted output
                             and structured result.
        remove_revoked_deprecated: Whether to exclude revoked and deprecated objects (default: True).

    Returns:
        {
          "count": <number of matching objects>,
          "objects": [
            {
              "attack_id": "<ATT&CK external ID or null>",
              "name": "<object name>",
              "stix_id": "<STIX ID>",
              "type": "<stix_type>",
              "description": "<description or null>"
            },
            ...
          ],
          "formatted": "<human-readable multi-object formatted text>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)
    norm_type = (stix_type or "").strip().lower()
    norm_name = (name or "").strip().lower()

    try:
        candidates = attack_data.get_objects_by_type(
            norm_type, remove_revoked_deprecated=remove_revoked_deprecated
        ) or []
        objs = [
            obj for obj in candidates
            if ((_stix_get(obj, "name", "") or "").strip().lower() == norm_name)
        ]
    except Exception:
        objs = []

    if not objs:
        return {
            "count": 0,
            "objects": [],
            "formatted": "",
            "message": (
                f"No objects found with name '{name}' and type '{norm_type}' "
                f"in domain '{domain}'."
            ),
        }

    structured_objects: List[Dict[str, Any]] = []

    for obj in objs:
        # Handle dict-like vs object-like forms
        if isinstance(obj, dict):
            obj_name = obj.get("name")
            stix_id = obj.get("id")
            obj_type = obj.get("type", stix_type)
            description = obj.get("description") if include_description else None
            stix_id_for_attack = stix_id
        else:
            obj_name = getattr(obj, "name", None)
            stix_id = getattr(obj, "id", None)
            obj_type = getattr(obj, "type", stix_type)
            description = getattr(obj, "description", None) if include_description else None
            stix_id_for_attack = stix_id

        # Try to resolve ATT&CK external ID (if any)
        attack_id = None
        if stix_id_for_attack:
            try:
                attack_id = attack_data.get_attack_id(stix_id_for_attack)
            except Exception:
                attack_id = None

        structured_objects.append(
            {
                "attack_id": attack_id,
                "name": obj_name,
                "stix_id": stix_id,
                "type": obj_type,
                "description": description,
            }
        )

    formatted = format_objects(
        objs,
        include_description=include_description,
        domain=domain,
    )

    return {
        "count": len(structured_objects),
        "objects": structured_objects,
        "formatted": formatted,
        "message": (
            f"Found {len(structured_objects)} object(s) with name '{name}' "
            f"and type '{stix_type}' in domain '{domain}'."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_objects_by_content(
    content: str,
    object_type: str = "all",
    domain: str = "enterprise",
    include_description: bool = True,
    remove_revoked_deprecated: bool = True,
    limit: PageLimit = DEFAULT_PAGE_LIMIT,
    offset: PageOffset = 0,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Search MITRE ATT&CK objects by matching text inside their description field.

    This performs a full-text search over object descriptions. It is useful for:
      • Finding techniques related to specific technologies (e.g., “PowerShell”)
      • Finding groups mentioning a region or country (e.g., “Russia”)
      • Finding mitigations referencing specific defenses (e.g., “multi-factor”)
      • Searching malware, tools, or procedure examples (relationships) for CVE IDs
        (e.g., "CVE-2021-44228") using object_type="all" or object_type="relationship"

    Args:
        content: The text to search for (case-insensitive, partial match).
        object_type: STIX object type, or "all" to search across all object types
            including relationships (procedure examples):
            - "all" (cross-type search including techniques, groups, software, relationships)
            - "relationship" (procedure examples, useful for CVE searches)
            - "attack-pattern" (techniques)
            - "intrusion-set" (APT groups)
            - "malware"
            - "tool"
            - "course-of-action" (mitigations)
            - "campaign"
            - "x-mitre-detection-strategy"
            - "x-mitre-analytic"
            - "x-mitre-data-component"
            - etc.
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to return descriptions in the structured output.
        remove_revoked_deprecated: Whether to exclude revoked and deprecated objects (default: True).
        limit: Maximum number of items to return per page (1-200).
        offset: Zero-based starting index for pagination (>= 0).
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
          "count": <number of matches in this page>,
          "total_count": <total number of matches>,
          "offset": <offset>,
          "limit": <limit>,
          "has_more": <bool>,
          "next_offset": <int or null>,
          "objects": [
             {
                "attack_id": "<ATT&CK ID or null>",
                "name": "<object name>",
                "stix_id": "<STIX ID>",
                "type": "<object_type>",
                "description": "<description or null>"
             },
             ...
          ],
          "formatted": "<human-readable formatted list>",
          "message": "<status message>"
        }
    """
    attack_data = get_attack_data(domain)
    safe_limit, safe_offset = _validate_pagination(limit, offset)
    norm_type = (object_type or "all").strip().lower()
    content_clean = (content or "").strip()

    if not content_clean:
        return {
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "objects": [],
            "formatted": "",
            "message": (
                f"No '{norm_type}' objects matched blank content query "
                f"in domain '{domain}'."
            ),
        }

    # Perform text search
    content_lower = content_clean.lower()
    objs: List[Any] = []
    if norm_type == "all":
        search_types = _ALL_RESOLVABLE_STIX_TYPES + ("relationship",)
        seen_ids: set[str] = set()
        for st in search_types:
            try:
                candidates = attack_data.get_objects_by_type(
                    st, remove_revoked_deprecated=remove_revoked_deprecated
                ) or []
            except Exception:
                candidates = []
            for item in candidates:
                obj = _unwrap_stix_object(item)
                if obj is None:
                    continue
                sid = _stix_get(obj, "id")
                if sid and sid in seen_ids:
                    continue
                desc = _stix_get(obj, "description") or ""
                if content_lower in str(desc).lower():
                    if sid:
                        seen_ids.add(sid)
                    objs.append(obj)
    elif norm_type == "relationship":
        try:
            candidates = attack_data.get_objects_by_type(
                "relationship", remove_revoked_deprecated=remove_revoked_deprecated
            ) or []
        except Exception:
            candidates = []
        for item in candidates:
            obj = _unwrap_stix_object(item)
            if obj is None:
                continue
            desc = _stix_get(obj, "description") or ""
            if content_lower in str(desc).lower():
                objs.append(obj)
    else:
        try:
            objs = attack_data.get_objects_by_content(
                content_clean,
                norm_type,
                remove_revoked_deprecated=remove_revoked_deprecated,
            ) or []
        except Exception:
            objs = []

    if not objs:
        return {
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "objects": [],
            "formatted": "",
            "message": (
                f"No {object_type} objects in domain '{domain}' contain the text '{content}'."
            ),
        }

    objs_sorted = sorted(
        objs,
        key=lambda o: (
            str(_stix_get(o, "type") or ""),
            str(_stix_get(o, "name") or ""),
            str(_stix_get(o, "id") or ""),
        ),
    )
    page_objs, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        objs_sorted, limit=limit, offset=offset
    )

    structured: List[Dict[str, Any]] = []

    for obj in page_objs:
        name = _stix_get(obj, "name")
        stix_id = _stix_get(obj, "id")
        stix_type = _stix_get(obj, "type", object_type)
        description = _stix_get(obj, "description") if include_description else None

        # Resolve external ATT&CK ID, if present
        try:
            attack_id = attack_data.get_attack_id(stix_id) if stix_id else None
        except Exception:
            attack_id = None

        entry: Dict[str, Any] = {
            "attack_id": attack_id,
            "name": name,
            "stix_id": stix_id,
            "type": stix_type,
            "description": description,
        }

        if stix_type == "relationship":
            src_ref = _stix_get(obj, "source_ref")
            tgt_ref = _stix_get(obj, "target_ref")
            rel_type = _stix_get(obj, "relationship_type")
            entry["relationship_type"] = rel_type
            entry["source_ref"] = src_ref
            entry["target_ref"] = tgt_ref
            for ref_key, ref_id in (("source", src_ref), ("target", tgt_ref)):
                ref_name = None
                ref_aid = None
                ref_type = ref_id.split("--")[0] if isinstance(ref_id, str) and "--" in ref_id else None
                if ref_id:
                    try:
                        ref_obj = attack_data.get_object_by_stix_id(ref_id)
                        if ref_obj is not None:
                            ref_name = _stix_get(ref_obj, "name")
                            ref_type = _stix_get(ref_obj, "type") or ref_type
                        ref_aid = attack_data.get_attack_id(ref_id)
                    except Exception:
                        pass
                entry[ref_key] = {
                    "attack_id": ref_aid,
                    "name": ref_name,
                    "stix_id": ref_id,
                    "type": ref_type,
                }

        structured.append(entry)

    # Human-readable output using your formatter
    formatted = (
        format_objects(
            page_objs,
            include_description=include_description,
            domain=domain,
        )
        if include_formatted
        else ""
    )

    return {
        "count": len(structured),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": next_offset,
        "objects": structured,
        "formatted": formatted,
        "message": (
            f"Found {total_count} '{object_type}' objects whose descriptions "
            f"contain the text '{content}' (returning {len(structured)} at offset {safe_offset})."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_techniques_by_tactic(
    tactic: str,
    domain: str = "enterprise",
    include_description: bool = True,
    limit: PageLimit = DEFAULT_PAGE_LIMIT,
    offset: PageOffset = 0,
    include_formatted: bool = True,
    platforms: Annotated[
        Optional[List[str]],
        Field(
            default=None,
            description=(
                "Optional list of target platforms (case-insensitive, e.g. ['Linux', 'Windows', 'ESXi', 'Containers']). "
                "When provided, filters techniques to those applicable to at least one requested platform "
                "and includes `applied_platforms` in the response."
            ),
        ),
    ] = None,
) -> Dict[str, Any]:
    """
    Get all techniques associated with a specific ATT&CK tactic.

    This uses the MITRE ATT&CK Navigator-style mapping between tactics and
    techniques for a given domain (e.g., "enterprise-attack").
    When an unrecognized tactic produces 0 matches, returns `available_tactics`
    listing valid tactic names for the requested domain so callers can self-correct in one step.

    Examples:
        - get_techniques_by_tactic("Initial Access", "enterprise")
        - get_techniques_by_tactic("Stealth", "enterprise")
        - get_techniques_by_tactic("Defense Impairment", "enterprise")
        - get_techniques_by_tactic("Persistence", "enterprise", platforms=["Linux"])

    Args:
        tactic: Tactic name (e.g., "Initial Access", "Stealth", "Defense Impairment", "Persistence").
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include technique descriptions
                             in the structured and formatted output.
        limit: Maximum number of items to return per page (1-200).
        offset: Zero-based starting index for pagination (>= 0).
        include_formatted: If False, omits the human-readable formatted block to save tokens.
        platforms: Optional list of platform names to filter techniques by `x_mitre_platforms`
                   (case-insensitive). Omit or pass None for all platforms.

    Returns:
        {
          "count": <number of techniques in this page>,
          "total_count": <total number of techniques>,
          "offset": <offset>,
          "limit": <limit>,
          "has_more": <bool>,
          "next_offset": <int or null>,
          "applied_platforms": ["<platform>", ...],  # included when platforms filter is applied
          "available_tactics": ["<tactic>", ...],    # included when 0 techniques match an unrecognized tactic
          "techniques": [
            {
              "attack_id": "<TXXXX or TXXXX.YYY>",
              "name": "<technique name>",
              "stix_id": "<attack-pattern--...>",
              "description": "<description or null>",
              "tactic": "<tactic name>",
            },
            ...
          ],
          "formatted": "<human-readable technique list>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)
    safe_limit, safe_offset = _validate_pagination(limit, offset)

    tactic_shortname = _normalize_tactic_shortname(attack_data, tactic)
    canonical_tactic = tactic
    available_tactics: List[str] = []
    try:
        tactic_names: set[str] = set()
        for t_obj in attack_data.get_tactics(remove_revoked_deprecated=True) or []:
            t_short = (_stix_get(t_obj, "x_mitre_shortname", "") or "").strip()
            t_name = (_stix_get(t_obj, "name", "") or "").strip()
            if t_name:
                tactic_names.add(t_name)
            if t_short.lower() == tactic_shortname.lower() or t_name.lower() == (tactic or "").strip().lower():
                if t_name:
                    canonical_tactic = t_name
        available_tactics = sorted(tactic_names)
    except Exception:
        available_tactics = []

    try:
        techniques = attack_data.get_techniques_by_tactic(
            tactic_shortname,
            f"{domain}-attack",
            remove_revoked_deprecated=True,
        )
    except Exception:
        techniques = []

    if not techniques:
        raw_applied_platforms = _normalize_technique_platforms(platforms)
        legacy = _LEGACY_TACTIC_MIGRATIONS.get((tactic or "").strip().lower())
        avail_str = ", ".join(available_tactics) if available_tactics else "none"
        if legacy:
            msg = (
                f"No techniques found for tactic '{canonical_tactic}' in domain '{domain}'. "
                f"{legacy['hint']} "
                f"Valid tactics for domain '{domain}': {avail_str}."
            )
        else:
            msg = (
                f"No techniques found for tactic '{canonical_tactic}' in domain '{domain}'. "
                f"Valid tactics for domain '{domain}': {avail_str}."
            )
        resp: Dict[str, Any] = {
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "techniques": [],
            "available_tactics": available_tactics,
            "formatted": "",
            "message": msg,
        }
        if legacy:
            resp["suggested_tactics"] = legacy["suggested_tactics"]
        if raw_applied_platforms is not None:
            resp["applied_platforms"] = raw_applied_platforms
        return resp

    applied_platforms = _normalize_technique_platforms(platforms, techniques)
    if applied_platforms is not None:
        platform_set_lower = {p.lower() for p in applied_platforms}
        techniques = [
            t for t in techniques if _technique_matches_platforms(t, platform_set_lower)
        ]
        if not techniques:
            try:
                domain_techniques = attack_data.get_techniques(remove_revoked_deprecated=True) or []
            except Exception:
                domain_techniques = []
            available_platforms = _extract_available_platforms(domain_techniques)
            suggested_platforms = _suggest_attack_platforms_for_list(
                applied_platforms, available_platforms
            )
            hint_clause = (
                f" Suggested ATT&CK platform(s): {', '.join(suggested_platforms)}."
                if suggested_platforms
                else ""
            )
            no_plat_resp: Dict[str, Any] = {
                "count": 0,
                "total_count": 0,
                "offset": safe_offset,
                "limit": safe_limit,
                "has_more": False,
                "next_offset": None,
                "applied_platforms": applied_platforms,
                "techniques": [],
                "formatted": "",
                "message": (
                    f"No techniques found for tactic '{canonical_tactic}' in domain '{domain}' "
                    f"(filtered by platforms: {', '.join(applied_platforms)}).{hint_clause}"
                ),
            }
            if suggested_platforms:
                no_plat_resp["suggested_platforms"] = suggested_platforms
            return no_plat_resp

    techniques_sorted = sorted(
        techniques,
        key=lambda t: (
            str(_stix_get(t, "name") or ""),
            str(_stix_get(t, "id") or ""),
        ),
    )
    page_techniques, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        techniques_sorted, limit=limit, offset=offset
    )

    structured: List[Dict[str, Any]] = []

    for tech in page_techniques:
        name = _stix_get(tech, "name")
        stix_id = _stix_get(tech, "id")
        description = _stix_get(tech, "description") if include_description else None

        # Resolve external ATT&CK ID (Txxxx / Txxxx.yyy)
        attack_id = None
        if stix_id:
            try:
                attack_id = attack_data.get_attack_id(stix_id)
            except Exception:
                attack_id = None

        structured.append(
            {
                "attack_id": attack_id,
                "name": name,
                "stix_id": stix_id,
                "description": description,
                "tactic": canonical_tactic,
            }
        )

    formatted = (
        format_objects(
            page_techniques,
            include_description=include_description,
            domain=domain,
        )
        if include_formatted
        else ""
    )

    plat_suffix = (
        f" (filtered by platforms: {', '.join(applied_platforms)})"
        if applied_platforms is not None
        else ""
    )
    result: Dict[str, Any] = {
        "count": len(structured),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": next_offset,
        "techniques": structured,
        "formatted": formatted,
        "message": (
            f"Found {total_count} technique(s) for tactic '{canonical_tactic}' "
            f"in domain '{domain}'{plat_suffix} (returning {len(structured)} at offset {safe_offset})."
        ),
    }
    if applied_platforms is not None:
        result["applied_platforms"] = applied_platforms
    return result

_DOMAIN_SORT_RANK: Dict[str, int] = {
    "enterprise": 0,
    "mobile": 1,
    "ics": 2,
}


def _format_cross_domain_techniques(
    items: List[Tuple[str, Any, Optional[str]]],
    include_description: bool = False,
) -> str:
    """Format cross-domain technique tuples (domain, stix_obj, attack_id) into a readable string."""
    blocks: List[str] = []
    for dom, obj, attack_id in items:
        obj = _unwrap_stix_object(obj)
        if obj is None:
            continue
        lines: List[str] = []
        name = _stix_get(obj, "name")
        if name:
            lines.append(f"Name: {name}")
        lines.append(f"Domain: {dom}")
        if attack_id:
            lines.append(f"ID: {attack_id}")
        stix_id = _stix_get(obj, "id")
        if stix_id:
            lines.append(f"STIX ID: {stix_id}")
        description = _stix_get(obj, "description")
        if include_description and description:
            lines.append(f"Description: {description}")
        blocks.append("\n".join(lines))
    return "\n---\n".join(blocks)


def _compact_cross_domain_provenance(
    domain_status: Dict[str, Dict[str, Any]],
    metadata: Dict[str, Any],
    ver_str: str,
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Any]]:
    """Build compact `domain_status` and `metadata` by hoisting shared provenance and preserving failure differentiation."""
    compact_ds: Dict[str, Dict[str, Any]] = {}
    for dom, ds in domain_status.items():
        if ds.get("status") == "OK" and ds.get("available") is True:
            compact_ds[dom] = {
                "status": "OK",
                "available": True,
                "match_count": ds.get("match_count"),
            }
        else:
            compact_ds[dom] = {
                "status": ds.get("status", "UNAVAILABLE"),
                "available": False,
                "match_count": ds.get("match_count"),
                "loaded_version": ds.get("loaded_version"),
                "source_url": ds.get("source_url"),
                "freshness_status": ds.get("freshness_status"),
                "error": ds.get("error"),
            }

    compact_meta: Dict[str, Any] = {
        "detail_level": "compact",
        "attack_version": metadata["attack_version"],
        "stix_spec_version": metadata["stix_spec_version"],
        "source_repository": metadata["source_repository"],
        "source_index_url": metadata["source_index_url"],
        "source_url_template": (
            f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
            f"master/{{domain}}-attack/{{domain}}-attack-{ver_str}.json"
        ),
        "source_release_date": metadata["source_release_date"],
        "source_release_date_known": metadata["source_release_date_known"],
        "freshness_status": metadata["freshness_status"],
        "complete": metadata["complete"],
        "partial": metadata["partial"],
        "unavailable_domains": list(metadata["unavailable_domains"]),
    }
    return compact_ds, compact_meta


def _search_techniques_all_domains(
    query: str,
    include_description: bool,
    limit: int,
    offset: int,
    include_formatted: bool,
    detail_level: str = "full",
    platforms: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Perform cross-domain search across enterprise, mobile, and ics local STIX bundles."""
    safe_limit, safe_offset = _validate_pagination(limit, offset)
    level = _validate_cross_domain_detail_level(detail_level)
    query_lower = (query or "").strip().lower()

    domain_status: Dict[str, Dict[str, Any]] = {}
    unavailable_domains: List[str] = []
    loaded_adapters: Dict[str, Any] = {}

    for dom in DOMAINS:
        stix_path = get_stix_path(dom)
        exists = stix_path.exists()
        if not exists:
            prov = _build_domain_provenance(dom, version=None, stix_path=stix_path, exists=False)
            domain_status[dom] = {
                "status": "UNAVAILABLE",
                "available": False,
                "match_count": None,
                "loaded_version": prov["loaded_version"],
                "stix_spec_version": prov["stix_spec_version"],
                "source_url": prov["source_url"],
                "source_release_date": prov["source_release_date"],
                "freshness_status": prov["freshness_status"],
                "error": f"STIX data file not found for domain '{dom}'.",
            }
            unavailable_domains.append(dom)
            continue

        try:
            ad = get_attack_data(dom)
            loaded_adapters[dom] = ad
            prov = _build_domain_provenance(
                dom,
                version=str(release_info.LATEST_VERSION),
                stix_path=stix_path,
                exists=True,
            )
            domain_status[dom] = {
                "status": "OK",
                "available": True,
                "match_count": 0,
                "loaded_version": prov["loaded_version"],
                "stix_spec_version": prov["stix_spec_version"],
                "source_url": prov["source_url"],
                "source_release_date": prov["source_release_date"],
                "freshness_status": prov["freshness_status"],
            }
        except Exception as e:
            prov = _build_domain_provenance(dom, version=None, stix_path=stix_path, exists=False)
            domain_status[dom] = {
                "status": "UNAVAILABLE",
                "available": False,
                "match_count": None,
                "loaded_version": None,
                "stix_spec_version": prov["stix_spec_version"],
                "source_url": None,
                "source_release_date": None,
                "freshness_status": "domain_load_failed",
                "error": f"Failed to load STIX data for domain '{dom}': {e}",
            }
            unavailable_domains.append(dom)

    ver_str = str(release_info.LATEST_VERSION)
    release_date = _KNOWN_SOURCE_RELEASE_DATES.get(ver_str)
    limitations = [
        "Serves the local STIX bundles pinned by mitreattack-python (release_info.LATEST_VERSION); does not poll upstream GitHub at runtime.",
        "Upstream currency beyond the loaded release is unknown without an external check against attack-stix-data.",
    ]

    def _finalize_response(resp: Dict[str, Any]) -> Dict[str, Any]:
        if level != "compact":
            return resp
        c_ds, c_meta = _compact_cross_domain_provenance(
            resp["domain_status"], resp["metadata"], ver_str
        )
        out: Dict[str, Any] = {}
        for k, v in resp.items():
            if k == "domain_status":
                out[k] = c_ds
            elif k == "metadata":
                out[k] = c_meta
            else:
                out[k] = v
            if k == "domains_searched":
                out["detail_level"] = "compact"
        return out

    if unavailable_domains:
        metadata_err = {
            "attack_version": ver_str,
            "stix_spec_version": "2.1",
            "source_repository": _SOURCE_REPOSITORY_URL,
            "source_index_url": _SOURCE_INDEX_URL,
            "source_release_date": release_date,
            "source_release_date_known": release_date is not None,
            "freshness_status": "incomplete_missing_domain_bundle",
            "complete": False,
            "partial": len(unavailable_domains) < len(DOMAINS),
            "unavailable_domains": list(unavailable_domains),
            "limitations": limitations,
        }
        return _finalize_response(
            {
                "found": False,
                "error_code": "DOMAIN_UNAVAILABLE",
                "domain": "all",
                "domains_searched": list(DOMAINS),
                "count": 0,
                "total_count": 0,
                "offset": safe_offset,
                "limit": safe_limit,
                "has_more": False,
                "next_offset": None,
                "techniques": [],
                "domain_status": domain_status,
                "metadata": metadata_err,
                "formatted": "",
                "message": (
                    f"Cross-domain search failed closed because domain(s) "
                    f"{', '.join(unavailable_domains)} are unavailable."
                ),
            }
        )

    metadata_ok = {
        "attack_version": ver_str,
        "stix_spec_version": "2.1",
        "source_repository": _SOURCE_REPOSITORY_URL,
        "source_index_url": _SOURCE_INDEX_URL,
        "source_release_date": release_date,
        "source_release_date_known": release_date is not None,
        "freshness_status": "pinned_local_release_upstream_unchecked",
        "complete": True,
        "partial": False,
        "unavailable_domains": [],
        "limitations": limitations,
    }

    if not query_lower:
        raw_applied = _normalize_technique_platforms(platforms)
        plat_suffix = (
            f" (filtered by platforms: {', '.join(raw_applied)})"
            if raw_applied is not None
            else ""
        )
        empty_resp: Dict[str, Any] = {
            "domain": "all",
            "domains_searched": list(DOMAINS),
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "techniques": [],
            "domain_status": domain_status,
            "metadata": metadata_ok,
            "formatted": "",
            "message": (
                f"No techniques across domains ({', '.join(DOMAINS)}) matched the query '{query}'{plat_suffix}."
            ),
        }
        if raw_applied is not None:
            empty_resp["applied_platforms"] = raw_applied
        return _finalize_response(empty_resp)

    # Load all domain techniques first so platform normalization can resolve canonical casing
    dom_techniques_map: Dict[str, List[Any]] = {}
    all_loaded_techniques: List[Any] = []
    for dom in DOMAINS:
        ad = loaded_adapters[dom]
        try:
            dom_techniques = ad.get_techniques(remove_revoked_deprecated=True) or []
            dom_techniques_map[dom] = dom_techniques
            all_loaded_techniques.extend(dom_techniques)
        except Exception as e:
            domain_status[dom]["status"] = "UNAVAILABLE"
            domain_status[dom]["available"] = False
            domain_status[dom]["match_count"] = None
            domain_status[dom]["error"] = f"Failed to query techniques for domain '{dom}': {e}"
            unavailable_domains.append(dom)
            continue

    applied_platforms = _normalize_technique_platforms(platforms, all_loaded_techniques)
    platform_set_lower = (
        {p.lower() for p in applied_platforms} if applied_platforms is not None else None
    )

    # Collect matches per domain without collapsing same name or same attack_id across domains
    matched_records: List[Tuple[str, Any, Optional[str], str, str]] = []
    for dom in DOMAINS:
        if dom not in dom_techniques_map:
            continue
        ad = loaded_adapters[dom]
        dom_techniques = dom_techniques_map[dom]

        dom_matches = 0
        for tech in dom_techniques:
            name = _stix_get(tech, "name") or ""
            description = _stix_get(tech, "description") or ""
            if query_lower in name.lower() or query_lower in description.lower():
                if platform_set_lower is not None and not _technique_matches_platforms(
                    tech, platform_set_lower
                ):
                    continue
                dom_matches += 1
                stix_id = _stix_get(tech, "id") or ""
                attack_id = None
                if stix_id:
                    try:
                        attack_id = ad.get_attack_id(stix_id)
                    except Exception:
                        attack_id = None
                matched_records.append((dom, tech, attack_id, str(name), str(stix_id)))
        domain_status[dom]["match_count"] = dom_matches

    if unavailable_domains:
        metadata_ok["complete"] = False
        metadata_ok["partial"] = len(unavailable_domains) < len(DOMAINS)
        metadata_ok["unavailable_domains"] = list(unavailable_domains)
        metadata_ok["freshness_status"] = "incomplete_missing_domain_bundle"
        err_resp: Dict[str, Any] = {
            "found": False,
            "error_code": "DOMAIN_UNAVAILABLE",
            "domain": "all",
            "domains_searched": list(DOMAINS),
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "techniques": [],
            "domain_status": domain_status,
            "metadata": metadata_ok,
            "formatted": "",
            "message": (
                f"Cross-domain search failed closed because domain(s) "
                f"{', '.join(unavailable_domains)} failed during retrieval."
            ),
        }
        if applied_platforms is not None:
            err_resp["applied_platforms"] = applied_platforms
        return _finalize_response(err_resp)

    plat_suffix = (
        f" (filtered by platforms: {', '.join(applied_platforms)})"
        if applied_platforms is not None
        else ""
    )

    if not matched_records:
        suggested_platforms: List[str] = []
        if applied_platforms is not None:
            available_platforms = _extract_available_platforms(all_loaded_techniques)
            suggested_platforms = _suggest_attack_platforms_for_list(
                applied_platforms, available_platforms
            )
        hint_clause = (
            f" Suggested ATT&CK platform(s): {', '.join(suggested_platforms)}."
            if suggested_platforms
            else ""
        )
        no_match_resp: Dict[str, Any] = {
            "domain": "all",
            "domains_searched": list(DOMAINS),
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "techniques": [],
            "domain_status": domain_status,
            "metadata": metadata_ok,
            "formatted": "",
            "message": (
                f"No techniques across domains ({', '.join(DOMAINS)}) matched the query '{query}'{plat_suffix}.{hint_clause}"
            ),
        }
        if applied_platforms is not None:
            no_match_resp["applied_platforms"] = applied_platforms
        if suggested_platforms:
            no_match_resp["suggested_platforms"] = suggested_platforms
        return _finalize_response(no_match_resp)

    # Deterministic global sort: name ascending, domain rank (enterprise, mobile, ics), attack_id, stix_id
    matched_sorted = sorted(
        matched_records,
        key=lambda rec: (
            rec[3],
            _DOMAIN_SORT_RANK.get(rec[0], 99),
            str(rec[2] or "").upper(),
            rec[4],
        ),
    )

    page_records, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        matched_sorted, limit=limit, offset=offset
    )

    structured: List[Dict[str, Any]] = []
    fmt_tuples: List[Tuple[str, Any, Optional[str]]] = []
    for dom, tech, attack_id, name, stix_id in page_records:
        description = _stix_get(tech, "description") if include_description else None
        structured.append(
            {
                "domain": dom,
                "attack_id": attack_id,
                "name": name,
                "stix_id": stix_id,
                "description": description,
            }
        )
        fmt_tuples.append((dom, tech, attack_id))

    formatted = (
        _format_cross_domain_techniques(
            fmt_tuples,
            include_description=include_description,
        )
        if include_formatted
        else ""
    )

    per_dom_summary = ", ".join(
        f"{dom}={domain_status[dom]['match_count']}" for dom in DOMAINS
    )
    ok_resp: Dict[str, Any] = {
        "domain": "all",
        "domains_searched": list(DOMAINS),
        "count": len(structured),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": next_offset,
        "techniques": structured,
        "domain_status": domain_status,
        "metadata": metadata_ok,
        "formatted": formatted,
        "message": (
            f"Found {total_count} technique(s) across domains ({per_dom_summary}) "
            f"matching query '{query}'{plat_suffix} (returning {len(structured)} at offset {safe_offset})."
        ),
    }
    if applied_platforms is not None:
        ok_resp["applied_platforms"] = applied_platforms
    return _finalize_response(ok_resp)


@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def search_techniques(
    query: str,
    domain: Annotated[
        str,
        Field(
            default="enterprise",
            description=(
                "ATT&CK domain to search: 'enterprise' (default), 'mobile', 'ics', "
                "or 'all' for cross-domain retrieval across Enterprise, Mobile, and ICS."
            ),
        ),
    ] = "enterprise",
    include_description: bool = True,
    limit: PageLimit = DEFAULT_PAGE_LIMIT,
    offset: PageOffset = 0,
    include_formatted: bool = True,
    detail_level: CrossDomainDetailLevel = "full",
    platforms: Annotated[
        Optional[List[str]],
        Field(
            default=None,
            description=(
                "Optional list of target platforms (case-insensitive, e.g. ['Linux', 'Windows', 'ESXi', 'Containers']). "
                "When provided, filters matching techniques to those applicable to at least one requested platform "
                "and includes `applied_platforms` in the response."
            ),
        ),
    ] = None,
) -> Dict[str, Any]:
    """
    Search MITRE ATT&CK techniques by keyword in their name or description.

    This tool performs a case-insensitive search over all non-revoked,
    non-deprecated techniques in the given domain (or across all three domains
    when `domain="all"`). A technique is matched if the query string appears in either:
      • the technique name, or
      • the technique description

    Cross-domain mode (`domain="all"`):
      • Searches Enterprise, Mobile, and ICS local STIX v20.1 bundles in one call.
      • Preserves per-hit `domain` disambiguation (never collapses techniques across domains).
      • Applies deterministic global ordering and global `offset`/`limit` pagination.
      • Includes `domain_status` and `metadata` provenance (release version, source release
        date, source URLs, and freshness limitations) and fails closed (`DOMAIN_UNAVAILABLE`)
        if any domain bundle is missing or fails to load.
      • Supports optional `detail_level='compact'` (or `'full'`, default `'full'`):
        - `'full'` (default): returns full per-domain provenance in `domain_status` and
          `limitations` in `metadata` (unchanged legacy response).
        - `'compact'`: deduplicates shared release provenance into `metadata` (with
          `source_url_template` so per-domain source URLs are derivable without repetition)
          and trims `domain_status[dom]` to `status`, `available`, and `match_count` on healthy
          domains while retaining full failure details on unavailable domains.

    Examples:
        - search_techniques("PowerShell")
        - search_techniques("credential dumping", platforms=["Linux", "Windows"])
        - search_techniques("initial access", domain="enterprise")
        - search_techniques("Command", domain="all", limit=10, include_description=False, include_formatted=False)
        - search_techniques("Screen Capture", domain="all", limit=10, include_description=False, include_formatted=False, detail_level="compact")

    Args:
        query: Text to search for in technique names and descriptions.
        domain: ATT&CK domain ("enterprise", "mobile", "ics", or "all").
        include_description: Whether to include descriptions in the structured
                             result and formatted output.
        limit: Maximum number of items to return per page (1-200).
        offset: Zero-based starting index for pagination (>= 0).
        include_formatted: If False, omits the human-readable formatted block to save tokens.
        detail_level: Cross-domain provenance detail level ("full" default, or "compact").
                      Ignored for single-domain calls.
        platforms: Optional list of platform names to filter matching techniques by
                   `x_mitre_platforms` (case-insensitive). Omit or pass None for all platforms.

    Returns:
        {
          "count": <number of matches in this page>,
          "total_count": <total number of matches>,
          "offset": <offset>,
          "limit": <limit>,
          "has_more": <bool>,
          "next_offset": <int or null>,
          "applied_platforms": ["<platform>", ...],  # included when platforms filter is applied
          "techniques": [
            {
              "attack_id": "<TXXXX or TXXXX.YYY>",
              "name": "<technique name>",
              "stix_id": "<attack-pattern--...>",
              "description": "<description or null>",
              "domain": "<enterprise|mobile|ics>"  # included when domain="all"
            },
            ...
          ],
          "formatted": "<human-readable formatted list>",
          "message": "<status summary>"
        }
    """
    _validate_cross_domain_detail_level(detail_level)
    norm_domain = (domain or "enterprise").strip().lower()
    if norm_domain == "all":
        return _search_techniques_all_domains(
            query=query,
            include_description=include_description,
            limit=limit,
            offset=offset,
            include_formatted=include_formatted,
            detail_level=detail_level,
            platforms=platforms,
        )

    attack_data = get_attack_data(domain)
    safe_limit, safe_offset = _validate_pagination(limit, offset)

    query_lower = (query or "").strip().lower()
    if not query_lower:
        raw_applied = _normalize_technique_platforms(platforms)
        plat_suffix = (
            f" (filtered by platforms: {', '.join(raw_applied)})"
            if raw_applied is not None
            else ""
        )
        empty_resp: Dict[str, Any] = {
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "techniques": [],
            "formatted": "",
            "message": (
                f"No techniques in domain '{domain}' matched the query '{query}'{plat_suffix}."
            ),
        }
        if raw_applied is not None:
            empty_resp["applied_platforms"] = raw_applied
        return empty_resp

    try:
        all_techniques = attack_data.get_techniques(remove_revoked_deprecated=True)
    except Exception:
        all_techniques = []

    applied_platforms = _normalize_technique_platforms(platforms, all_techniques)
    platform_set_lower = (
        {p.lower() for p in applied_platforms} if applied_platforms is not None else None
    )

    matched: List[Any] = []

    for tech in all_techniques:
        name = (_stix_get(tech, "name") or "")
        description = (_stix_get(tech, "description") or "")

        if query_lower in name.lower() or query_lower in description.lower():
            if platform_set_lower is not None and not _technique_matches_platforms(
                tech, platform_set_lower
            ):
                continue
            matched.append(tech)

    plat_suffix = (
        f" (filtered by platforms: {', '.join(applied_platforms)})"
        if applied_platforms is not None
        else ""
    )

    if not matched:
        suggested_platforms: List[str] = []
        if applied_platforms is not None:
            available_platforms = _extract_available_platforms(all_techniques)
            suggested_platforms = _suggest_attack_platforms_for_list(
                applied_platforms, available_platforms
            )
        hint_clause = (
            f" Suggested ATT&CK platform(s): {', '.join(suggested_platforms)}."
            if suggested_platforms
            else ""
        )
        no_match_resp: Dict[str, Any] = {
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "techniques": [],
            "formatted": "",
            "message": (
                f"No techniques in domain '{domain}' matched the query '{query}'{plat_suffix}.{hint_clause}"
            ),
        }
        if applied_platforms is not None:
            no_match_resp["applied_platforms"] = applied_platforms
        if suggested_platforms:
            no_match_resp["suggested_platforms"] = suggested_platforms
        return no_match_resp

    matched_sorted = sorted(
        matched,
        key=lambda t: (
            str(_stix_get(t, "name") or ""),
            str(_stix_get(t, "id") or ""),
        ),
    )
    page_matched, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        matched_sorted, limit=limit, offset=offset
    )

    structured: List[Dict[str, Any]] = []

    for tech in page_matched:
        name = _stix_get(tech, "name")
        stix_id = _stix_get(tech, "id")
        description = _stix_get(tech, "description") if include_description else None

        # Resolve ATT&CK external ID
        attack_id = None
        if stix_id:
            try:
                attack_id = attack_data.get_attack_id(stix_id)
            except Exception:
                attack_id = None

        structured.append(
            {
                "attack_id": attack_id,
                "name": name,
                "stix_id": stix_id,
                "description": description,
            }
        )

    formatted = (
        format_objects(
            page_matched,
            include_description=include_description,
            domain=domain,
        )
        if include_formatted
        else ""
    )

    result: Dict[str, Any] = {
        "count": len(structured),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": next_offset,
        "techniques": structured,
        "formatted": formatted,
        "message": (
            f"Found {total_count} technique(s) in domain '{domain}' "
            f"matching query '{query}'{plat_suffix} (returning {len(structured)} at offset {safe_offset})."
        ),
    }
    if applied_platforms is not None:
        result["applied_platforms"] = applied_platforms
    return result

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_group_by_name(
    group_name: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Retrieve an intrusion set (APT group) by name or alias (case-insensitive match).

    This tool searches ATT&CK intrusion sets by name or alias and returns the first
    matching group. Matching is case-insensitive and supports partial matches.

    Examples:
        - get_group_by_name("APT29")
        - get_group_by_name("Lazarus")
        - get_group_by_name("Fancy Bear")

    Args:
        group_name: The group name or alias to search for (case-insensitive).
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include descriptions in the output.

    Returns:
        {
          "found": bool,
          "group": {
              "attack_id": "<GXXXX>",
              "name": "<group name>",
              "aliases": [...],
              "stix_id": "<intrusion-set--...>",
              "description": "<description or null>"
          },
          "formatted": "<human-readable text>",
          "message": "<status>"
        }
    """
    attack_data = get_attack_data(domain)

    try:
        groups = attack_data.get_groups(remove_revoked_deprecated=True)
    except Exception:
        groups = []

    query = (group_name or "").strip().lower()
    exact_matches = []
    partial_matches = []

    for grp in groups:
        name = (_stix_get(grp, "name", "") or "").lower()
        aliases = [a.lower() for a in (_stix_get(grp, "aliases", []) or [])]

        if query == name or query in aliases:
            exact_matches.append(grp)
        elif query and (query in name or any(query in alias for alias in aliases)):
            partial_matches.append(grp)

    match = exact_matches[0] if exact_matches else (partial_matches[0] if partial_matches else None)
    ambiguous_candidates = [
        _stix_get(g, "name") for g in (exact_matches if exact_matches else partial_matches)[:6]
    ]
    total_matches = len(exact_matches) if exact_matches else len(partial_matches)

    if match is None:
        return {
            "found": False,
            "group": None,
            "formatted": "",
            "message": (
                f"No intrusion set (APT group) found matching '{group_name}' "
                f"in domain '{domain}'."
            ),
        }

    # Extract fields consistently
    if isinstance(match, dict):
        name = match.get("name")
        stix_id = match.get("id")
        aliases = match.get("aliases", [])
        description = match.get("description") if include_description else None
    else:
        name = getattr(match, "name", None)
        stix_id = getattr(match, "id", None)
        aliases = getattr(match, "aliases", [])
        description = getattr(match, "description", None) if include_description else None

    # Resolve external attack ID (e.g., G0016)
    attack_id = None
    try:
        attack_id = attack_data.get_attack_id(stix_id)
    except Exception:
        pass

    formatted = format_objects(
        [match],
        include_description=include_description,
        domain=domain,
    )

    msg = (
        f"Found intrusion set '{name}' ({attack_id}) matching '{group_name}' "
        f"in domain '{domain}'."
    )
    if total_matches > 1:
        msg += (
            f" Note: {total_matches} groups matched '{group_name}' "
            f"(examples: {', '.join(c for c in ambiguous_candidates if c)}). "
            "Use search_groups for the full list."
        )
    return {
        "found": True,
        "match_count": total_matches,
        "group": {
            "attack_id": attack_id,
            "name": name,
            "aliases": aliases,
            "stix_id": stix_id,
            "description": description,
        },
        "formatted": formatted,
        "message": msg,
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_stix_type(
    stix_id: str,
    domain: str = "enterprise",
) -> Dict[str, Any]:
    """
    Determine the STIX object type for a given STIX ID.

    This is useful when you have a raw STIX UUID (e.g.,
    "attack-pattern--xxxx") but need to know whether it corresponds to a
    technique, intrusion set, malware, tool, mitigation, data source, etc.

    Args:
        stix_id: The STIX UUID identifier to look up.
        domain: ATT&CK domain ("enterprise", "mobile", "ics").

    Returns:
        {
            "found": bool,
            "stix_type": "<type string or null>",
            "message": "<status message>"
        }

    Examples:
        get_stix_type("attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b")
        → "attack-pattern"
    """
    attack_data = get_attack_data(domain)

    try:
        parsed_type = attack_data.get_stix_type(stix_id)
    except Exception:
        parsed_type = None

    try:
        obj = attack_data.get_object_by_stix_id(stix_id)
    except Exception:
        obj = None

    if obj is None:
        return {
            "found": False,
            "exists_in_domain": False,
            "stix_type": None,
            "parsed_type": parsed_type,
            "message": (
                f"No STIX object found for ID '{stix_id}' in domain '{domain}'"
                + (f" (ID prefix parses as '{parsed_type}')." if parsed_type else ".")
            ),
        }

    actual_type = _stix_get(obj, "type") or parsed_type
    return {
        "found": True,
        "exists_in_domain": True,
        "stix_type": actual_type,
        "parsed_type": parsed_type,
        "message": f"STIX object type for '{stix_id}' is '{actual_type}'.",
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def search_groups(
    query: str = "",
    domain: str = "enterprise",
    include_description: bool = True,
    limit: PageLimit = DEFAULT_PAGE_LIMIT,
    offset: PageOffset = 0,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Search MITRE ATT&CK intrusion sets (APT groups) by name, alias, or
    description (case-insensitive).

    If the query is empty, all groups in the domain are returned.

    Args:
        query: Search keyword (name, alias, or any text in the description).
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include descriptions in the output.
        limit: Maximum number of items to return per page (1-200).
        offset: Zero-based starting index for pagination (>= 0).
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
          "count": <number of matches in this page>,
          "total_count": <total number of matches>,
          "offset": <offset>,
          "limit": <limit>,
          "has_more": <bool>,
          "next_offset": <int or null>,
          "groups": [
            {
              "attack_id": "GXXXX",
              "name": "...",
              "aliases": [...],
              "stix_id": "...",
              "description": "..." | null
            },
            ...
          ],
          "formatted": "<LLM-friendly block>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)
    safe_limit, safe_offset = _validate_pagination(limit, offset)

    try:
        groups = attack_data.get_groups(remove_revoked_deprecated=True)
    except Exception:
        groups = []

    # Empty query → return all groups
    query_lower = (query or "").lower().strip()
    matched = []

    for grp in groups:
        name = (_stix_get(grp, "name") or "").lower()
        description = (_stix_get(grp, "description") or "").lower()
        aliases = [a.lower() for a in _get_aliases(grp)]

        if not query_lower:
            matched.append(grp)
            continue

        if (
            query_lower in name
            or query_lower in description
            or any(query_lower in a for a in aliases)
        ):
            matched.append(grp)

    # If nothing matched
    if not matched:
        return {
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "groups": [],
            "formatted": "",
            "message": f"No APT groups in domain '{domain}' matched query '{query}'.",
        }

    matched_sorted = sorted(
        matched,
        key=lambda g: (
            str(_stix_get(g, "name") or ""),
            str(_stix_get(g, "id") or ""),
        ),
    )
    page_matched, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        matched_sorted, limit=limit, offset=offset
    )

    # Build structured output
    response_groups = []
    for grp in page_matched:
        name = _stix_get(grp, "name")
        stix_id = _stix_get(grp, "id")
        aliases = _get_aliases(grp)
        description = _stix_get(grp, "description") if include_description else None

        # Resolve ATT&CK external ID (e.g., G0016)
        try:
            attack_id = attack_data.get_attack_id(stix_id) if stix_id else None
        except Exception:
            attack_id = None

        response_groups.append(
            {
                "attack_id": attack_id,
                "name": name,
                "aliases": aliases,
                "stix_id": stix_id,
                "description": description,
            }
        )

    formatted = (
        format_objects(
            page_matched,
            include_description=include_description,
            domain=domain,
        )
        if include_formatted
        else ""
    )

    return {
        "count": len(response_groups),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": next_offset,
        "groups": response_groups,
        "formatted": formatted,
        "message": (
            f"Found {total_count} APT group(s) in domain '{domain}' "
            f"matching query '{query}' (returning {len(response_groups)} at offset {safe_offset})."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_group_techniques(
    group_name: str,
    domain: str = "enterprise",
    include_description: bool = True,
    limit: PageLimit = DEFAULT_PAGE_LIMIT,
    offset: PageOffset = 0,
    include_formatted: bool = True,
    include_relationships: bool = True,
    attribution_filter: AttributionFilter = "all",
) -> Dict[str, Any]:
    """
    Get all techniques used by a specific APT group (intrusion set), with pagination.

    This tool:
      1) Locates a group by name or alias (exact match first, case-insensitive).
      2) Uses MITRE's get_techniques_used_by_group() to retrieve techniques
         related to that group (directly or via attributed campaigns), sorted
         deterministically by attack_id ascending.

    Args:
        group_name: Group name or alias (e.g., "APT29", "Lazarus Group").
        domain: ATT&CK domain ("enterprise", "mobile", or "ics").
        include_description: Whether to include descriptions in the output.
        limit: Maximum number of techniques to return per page (1-200).
        offset: Zero-based starting index for pagination (>= 0).
        include_formatted: If False, omits the human-readable formatted block to save tokens.
        include_relationships: If False, returns empty relationship arrays per technique to reduce payload size while preserving attribution_source.
        attribution_filter: Filter by attribution provenance ('all', 'direct', or 'campaign').

    Returns:
        {
          "found": bool,  # whether the group was found
          "group": {
              "attack_id": "GXXXX",
              "name": "...",
              "aliases": [...],
              "stix_id": "intrusion-set--...",
              "description": "..." | null
          } | null,
          "count": <number of techniques in this page>,
          "total_count": <total number of techniques>,
          "offset": <page offset>,
          "limit": <page limit>,
          "has_more": bool,
          "next_offset": int | null,
          "techniques": [
            {
              "attack_id": "TXXXX or TXXXX.YYY",
              "name": "...",
              "stix_id": "attack-pattern--...",
              "description": "..." | null,
              "attribution_source": "direct" | "campaign" | "both",
              "relationships": [
                {
                  "stix_id": "relationship--...",
                  "relationship_type": "uses",
                  "description": "..." | null,
                  "source_ref": "...",
                  "target_ref": "..."
                },
                ...
              ]
            },
            ...
          ],
          "formatted": "<human-readable technique list>",
          "message": "<status summary>"
        }
    """
    safe_limit, safe_offset = _validate_pagination(limit, offset)
    safe_attr_filter = _validate_attribution_filter(attribution_filter)
    attack_data = get_attack_data(domain)

    # --- 1) Find the group by name or alias (exact match first, same semantics as get_group_by_name) ---
    try:
        groups = attack_data.get_groups(remove_revoked_deprecated=True)
    except Exception:
        groups = []

    query = (group_name or "").strip().lower()
    exact_matches = []
    partial_matches = []

    for grp in groups:
        name = (_stix_get(grp, "name", "") or "").lower()
        aliases = [a.lower() for a in (_stix_get(grp, "aliases", []) or [])]

        if query and (query == name or query in aliases):
            exact_matches.append(grp)
        elif query and (query in name or any(query in alias for alias in aliases)):
            partial_matches.append(grp)

    group = exact_matches[0] if exact_matches else (partial_matches[0] if partial_matches else None)

    if group is None:
        return {
            "found": False,
            "group": None,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "techniques": [],
            "formatted": "",
            "message": (
                f"No intrusion set (APT group) found matching '{group_name}' "
                f"in domain '{domain}'."
            ),
        }

    # Extract basic group fields
    if isinstance(group, dict):
        group_name_val = group.get("name")
        group_stix_id = group.get("id")
        group_aliases = group.get("aliases", [])
        group_desc = group.get("description") if include_description else None
    else:
        group_name_val = getattr(group, "name", None)
        group_stix_id = getattr(group, "id", None)
        group_aliases = getattr(group, "aliases", [])
        group_desc = getattr(group, "description", None) if include_description else None

    try:
        group_attack_id = attack_data.get_attack_id(group_stix_id)
    except Exception:
        group_attack_id = None

    # --- 2) Get techniques used by this group ---
    try:
        rel_entries = attack_data.get_techniques_used_by_group(group_stix_id)
    except Exception:
        rel_entries = []

    # rel_entries is a list of RelationshipEntry[AttackPattern]:
    # each entry is like { "object": <Technique>, "relationships": [<Relationship>, ...] }

    normalized_entries: List[Tuple[Tuple[int, str, str, str], Any, Optional[str], Optional[str], Optional[str], str, List[Dict[str, Any]]]] = []

    for entry in rel_entries:
        if isinstance(entry, dict):
            tech_obj = entry.get("object")
            rels = entry.get("relationships", [])
        else:
            tech_obj = getattr(entry, "object", None)
            rels = getattr(entry, "relationships", [])

        if tech_obj is None:
            continue

        relationships_info = [_format_rel_edge(r, include_description=include_description) for r in rels]
        attribution_source = _classify_group_technique_attribution(relationships_info, group_stix_id)
        if not _matches_attribution_filter(attribution_source, safe_attr_filter):
            continue

        t_name = _stix_get(tech_obj, "name")
        t_stix_id = _stix_get(tech_obj, "id")
        try:
            t_attack_id = attack_data.get_attack_id(t_stix_id) if t_stix_id else None
        except Exception:
            t_attack_id = None

        normalized_entries.append(
            (
                _attack_id_sort_key(t_attack_id, t_name, t_stix_id),
                tech_obj,
                t_attack_id,
                t_name,
                t_stix_id,
                attribution_source,
                relationships_info if include_relationships else [],
            )
        )

    normalized_entries.sort(key=lambda item: item[0])
    page_entries, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        normalized_entries, limit=limit, offset=offset
    )

    techniques_structured: List[Dict[str, Any]] = []
    technique_objects_for_format: List[Any] = []

    for _sort_key, tech_obj, t_attack_id, t_name, t_stix_id, attribution_source, relationships_info in page_entries:
        technique_objects_for_format.append(tech_obj)
        t_desc = _stix_get(tech_obj, "description") if include_description else None

        techniques_structured.append(
            {
                "attack_id": t_attack_id,
                "name": t_name,
                "stix_id": t_stix_id,
                "description": t_desc,
                "attribution_source": attribution_source,
                "relationships": relationships_info,
            }
        )

    formatted = ""
    if include_formatted and technique_objects_for_format:
        formatted = format_objects(
            technique_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "found": True,
        "group": {
            "attack_id": group_attack_id,
            "name": group_name_val,
            "aliases": group_aliases,
            "stix_id": group_stix_id,
            "description": group_desc,
        },
        "count": len(techniques_structured),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": next_offset,
        "techniques": techniques_structured,
        "formatted": formatted,
        "message": (
            f"Found {total_count} technique(s) used by group "
            f"'{group_name}' in domain '{domain}' "
            f"(returning {len(techniques_structured)} at offset {safe_offset})."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_software(
    domain: str = "enterprise",
    include_description: bool = False,
    limit: PageLimit = DEFAULT_PAGE_LIMIT,
    offset: PageOffset = 0,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Get all software (malware and tools) in a given ATT&CK domain.

    This returns non-revoked, non-deprecated software objects, including
    both malware and tools, as defined by the MITRE ATT&CK dataset.

    Args:
        domain: ATT&CK domain to search ("enterprise", "mobile", or "ics").
        include_description: Whether to include descriptions in the output and
                             formatted text.
        limit: Maximum number of items to return per page (1-200).
        offset: Zero-based starting index for pagination (>= 0).
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
          "count": <number of software objects in this page>,
          "total_count": <total number of software objects>,
          "offset": <offset>,
          "limit": <limit>,
          "has_more": <bool>,
          "next_offset": <int or null>,
          "software": [
            {
              "attack_id": "<SXXXX or similar, if present>",
              "name": "<software name>",
              "aliases": [...],
              "stix_id": "<STIX ID>",
              "type": "<malware|tool|...>",
              "description": "<text or null>"
            },
            ...
          ],
          "formatted": "<human-readable list>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)
    safe_limit, safe_offset = _validate_pagination(limit, offset)

    try:
        software_objs = attack_data.get_software(remove_revoked_deprecated=True)
    except Exception:
        software_objs = []

    if not software_objs:
        return {
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "software": [],
            "formatted": "",
            "message": f"No software objects found in domain '{domain}'.",
        }

    software_sorted = sorted(
        software_objs,
        key=lambda o: (
            str(_stix_get(o, "name") or ""),
            str(_stix_get(o, "id") or ""),
        ),
    )
    page_software, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        software_sorted, limit=limit, offset=offset
    )

    software_list: List[Dict[str, Any]] = []

    for obj in page_software:
        name = _stix_get(obj, "name")
        stix_id = _stix_get(obj, "id")
        stix_type = _stix_get(obj, "type")
        aliases = _get_aliases(obj)
        description = _stix_get(obj, "description") if include_description else None

        # External ATT&CK ID (e.g., SXXXX)
        attack_id = None
        if stix_id:
            try:
                attack_id = attack_data.get_attack_id(stix_id)
            except Exception:
                attack_id = None

        software_list.append(
            {
                "attack_id": attack_id,
                "name": name,
                "aliases": aliases,
                "stix_id": stix_id,
                "type": stix_type,
                "description": description,
            }
        )

    formatted = (
        format_objects(
            page_software,
            include_description=include_description,
            domain=domain,
        )
        if include_formatted
        else ""
    )

    return {
        "count": len(software_list),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": next_offset,
        "software": software_list,
        "formatted": formatted,
        "message": (
            f"Found {total_count} software object(s) "
            f"in domain '{domain}' (returning {len(software_list)} at offset {safe_offset})."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def search_software(
    query: str,
    domain: str = "enterprise",
    include_description: bool = True,
    limit: PageLimit = DEFAULT_PAGE_LIMIT,
    offset: PageOffset = 0,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Search MITRE ATT&CK software (malware & tools) by keyword in name or
    description (case-insensitive).

    Args:
        query: Keyword to search for in software names and descriptions.
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include descriptions in the response.
        limit: Maximum number of items to return per page (1-200).
        offset: Zero-based starting index for pagination (>= 0).
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
          "count": <number of matches in this page>,
          "total_count": <total number of matches>,
          "offset": <offset>,
          "limit": <limit>,
          "has_more": <bool>,
          "next_offset": <int or null>,
          "software": [
            {
              "attack_id": "<SXXXX or similar>",
              "name": "...",
              "aliases": [...],
              "stix_id": "...",
              "type": "<tool|malware|...>",
              "description": "..." | null
            },
            ...
          ],
          "formatted": "<nicely formatted block>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)
    safe_limit, safe_offset = _validate_pagination(limit, offset)

    # Load all software objects
    try:
        all_sw = attack_data.get_software(remove_revoked_deprecated=True)
    except Exception:
        all_sw = []

    if not all_sw:
        return {
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "software": [],
            "formatted": "",
            "message": f"No software found in domain '{domain}'.",
        }

    query_lower = (query or "").strip().lower()
    if not query_lower:
        return {
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "software": [],
            "formatted": "",
            "message": (
                f"No software objects in domain '{domain}' matched query '{query}'."
            ),
        }

    matched = []

    # Software search loop
    for sw in all_sw:
        name = (_stix_get(sw, "name") or "").lower()
        description = (_stix_get(sw, "description") or "").lower()

        if query_lower in name or query_lower in description:
            matched.append(sw)

    if not matched:
        return {
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "software": [],
            "formatted": "",
            "message": (
                f"No software objects in domain '{domain}' matched query '{query}'."
            ),
        }

    matched_sorted = sorted(
        matched,
        key=lambda o: (
            str(_stix_get(o, "name") or ""),
            str(_stix_get(o, "id") or ""),
        ),
    )
    page_matched, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        matched_sorted, limit=limit, offset=offset
    )

    # Build structured output
    structured = []

    for sw in page_matched:
        name = _stix_get(sw, "name")
        stix_id = _stix_get(sw, "id")
        sw_type = _stix_get(sw, "type")
        aliases = _get_aliases(sw)
        desc = _stix_get(sw, "description") if include_description else None

        # ATT&CK external ID (SXXXX)
        try:
            attack_id = attack_data.get_attack_id(stix_id) if stix_id else None
        except Exception:
            attack_id = None

        structured.append(
            {
                "attack_id": attack_id,
                "name": name,
                "aliases": aliases,
                "stix_id": stix_id,
                "type": sw_type,
                "description": desc,
            }
        )

    formatted = (
        format_objects(
            page_matched,
            include_description=include_description,
            domain=domain,
        )
        if include_formatted
        else ""
    )

    return {
        "count": len(structured),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": next_offset,
        "software": structured,
        "formatted": formatted,
        "message": (
            f"Found {total_count} software object(s) in domain '{domain}' "
            f"matching '{query}' (returning {len(structured)} at offset {safe_offset})."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_attack_id(
    stix_id: str,
    domain: str = "enterprise",
) -> Dict[str, Any]:
    """
    Convert a STIX UUID into its human-readable ATT&CK ID.

    This tool resolves internal STIX identifiers such as:
        attack-pattern--UUID
        malware--UUID
        intrusion-set--UUID
        tool--UUID
        course-of-action--UUID

    into ATT&CK IDs such as:
        T1566      (Technique)
        T1055.002  (Sub-technique)
        G0016      (Group)
        S0154      (Software)
        M1013      (Mitigation)

    Args:
        stix_id: Full STIX UUID identifier.
        domain: ATT&CK domain ("enterprise", "mobile", "ics").

    Returns:
        {
          "found": bool,
          "attack_id": "<ATT&CK ID or null>",
          "message": "<status message>"
        }
    """
    attack_data = get_attack_data(domain)

    try:
        attack_id = attack_data.get_attack_id(stix_id)
    except Exception:
        attack_id = None

    if attack_id is None:
        return {
            "found": False,
            "attack_id": None,
            "message": (
                f"No ATT&CK ID found for STIX ID '{stix_id}' "
                f"in domain '{domain}'."
            ),
        }

    return {
        "found": True,
        "attack_id": attack_id,
        "message": (
            f"Resolved STIX ID '{stix_id}' to ATT&CK ID '{attack_id}' "
            f"in domain '{domain}'."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_name(
    stix_id: str,
    domain: str = "enterprise",
) -> Dict[str, Any]:
    """
    Resolve the human-readable object name for a given STIX ID.

    This converts internal STIX UUIDs such as:
        attack-pattern--UUID
        intrusion-set--UUID
        malware--UUID
        tool--UUID
        course-of-action--UUID

    into ATT&CK object names such as:
        "Phishing"
        "APT29"
        "Cobalt Strike"
        "Valid Accounts"

    Args:
        stix_id: STIX UUID of the object.
        domain: ATT&CK domain ("enterprise", "mobile", "ics").

    Returns:
        {
          "found": bool,
          "name": "<object name or null>",
          "message": "<status message>"
        }
    """
    attack_data = get_attack_data(domain)

    try:
        name = attack_data.get_name(stix_id)
    except Exception:
        name = None

    if not name:
        return {
            "found": False,
            "name": None,
            "message": (
                f"No ATT&CK object name found for STIX ID '{stix_id}' "
                f"in domain '{domain}'."
            ),
        }

    return {
        "found": True,
        "name": name,
        "message": (
            f"Resolved STIX ID '{stix_id}' to object name '{name}' "
            f"in domain '{domain}'."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_technique_tactics(
    technique_id: str,
    domain: str = "enterprise",
) -> Dict[str, Any]:
    """
    Get the ATT&CK tactic names associated with a given technique.

    This tool:
      1) Looks up a technique by its external ATT&CK ID (e.g., "T1055").
      2) Extracts its kill chain phases (tactics) from the STIX object.
      3) Returns human-readable tactic names (e.g., "Initial Access"),
         along with the raw phase names and kill chain names.

    Args:
        technique_id: External ATT&CK technique ID (e.g., "T1055", "T1055.002").
        domain: ATT&CK domain ("enterprise", "mobile", "ics").

    Returns:
        {
          "found": bool,
          "technique": {
              "id": "<ATT&CK ID>",
              "name": "<technique name or null>",
              "stix_id": "<attack-pattern--... or null>",
          } | null,
          "tactics": [
            {
              "tactic": "<Human readable, e.g., 'Initial Access'>",
              "phase_name": "<raw phase name, e.g., 'initial-access'>",
              "kill_chain_name": "<kill chain name, e.g., 'mitre-attack'>"
            },
            ...
          ],
          "message": "<status message>"
        }
    """
    attack_data = get_attack_data(domain)
    norm_id = (technique_id or "").strip().upper()

    # 1) Look up the technique by ATT&CK ID
    try:
        tech = attack_data.get_object_by_attack_id(norm_id, "attack-pattern")
    except Exception:
        tech = None

    if tech is None:
        return {
            "found": False,
            "technique": None,
            "tactics": [],
            "message": (
                f"Technique '{norm_id}' not found in domain '{domain}'."
            ),
        }

    # 2) Extract basic technique fields
    if isinstance(tech, dict):
        tech_name = tech.get("name")
        tech_stix_id = tech.get("id")
        phases = tech.get("kill_chain_phases", []) or []
    else:
        tech_name = getattr(tech, "name", None)
        tech_stix_id = getattr(tech, "id", None)
        phases = getattr(tech, "kill_chain_phases", []) or []

    canonical_id = norm_id
    if tech_stix_id:
        try:
            canonical_id = attack_data.get_attack_id(tech_stix_id) or norm_id
        except Exception:
            canonical_id = norm_id

    # 3) Normalize phases into tactic objects
    tactics: List[Dict[str, Any]] = []

    for phase in phases:
        # Handle dict-like vs object-like phase entries
        if isinstance(phase, dict):
            phase_name = phase.get("phase_name", "")
            kill_chain_name = phase.get("kill_chain_name", "")
        else:
            phase_name = getattr(phase, "phase_name", "") or ""
            kill_chain_name = getattr(phase, "kill_chain_name", "") or ""

        # Human-readable tactic label, e.g. "initial-access" -> "Initial Access"
        tactic_label = phase_name.replace("-", " ").title() if phase_name else None

        tactics.append(
            {
                "tactic": tactic_label,
                "phase_name": phase_name,
                "kill_chain_name": kill_chain_name,
            }
        )

    # 4) Return structured result
    return {
        "found": True,
        "technique": {
            "id": canonical_id,
            "name": tech_name,
            "stix_id": tech_stix_id,
        },
        "tactics": tactics,
        "message": (
            f"Found {len(tactics)} tactic phase(s) for technique '{canonical_id}' "
            f"in domain '{domain}'."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_stats(
    domain: str = "enterprise",
) -> Dict[str, Any]:
    """
    Get basic statistics about the loaded ATT&CK data for a given domain.

    This returns counts of key object types (techniques, groups, software,
    tactics, mitigations), excluding revoked/deprecated entries.

    Args:
        domain: ATT&CK domain ("enterprise", "mobile", "ics").

    Returns:
        {
          "domain": "<domain>",
          "stats": {
              "techniques": <int>,
              "groups": <int>,
              "software": <int>,
              "tactics": <int>,
              "mitigations": <int>
          },
          "message": "<status message>"
        }
    """
    domain_norm = (domain or "enterprise").strip().lower()
    attack_data = get_attack_data(domain_norm)

    def safe_count(getter) -> int:
        try:
            return len(getter(remove_revoked_deprecated=True))
        except Exception:
            return 0

    stats = {
        "techniques": safe_count(attack_data.get_techniques),
        "groups": safe_count(attack_data.get_groups),
        "software": safe_count(attack_data.get_software),
        "tactics": safe_count(attack_data.get_tactics),
        "mitigations": safe_count(attack_data.get_mitigations),
    }

    return {
        "domain": domain_norm,
        "stats": stats,
        "provenance": _build_domain_provenance(domain_norm),
        "message": (
            f"ATT&CK object statistics for domain '{domain_norm}': "
            f"{stats['techniques']} techniques, "
            f"{stats['groups']} groups, "
            f"{stats['software']} software, "
            f"{stats['tactics']} tactics, "
            f"{stats['mitigations']} mitigations."
        ),
    }
#####################################################################
    # Threat Actor Group functions
#####################################################################

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_groups_by_alias(
    alias: str,
    domain: str = "enterprise",
    include_description: bool = True,
    remove_revoked_deprecated: bool = True,
) -> Dict[str, Any]:
    """
    Get APT groups (intrusion sets) matching a given alias.

    Many groups have multiple aliases—e.g., APT29 is also known as:
    "Cozy Bear", "NOBELIUM", "Midnight Blizzard", etc.
    
    This tool returns all groups whose alias list contains the given alias
    (case-insensitive exact match, per MITRE's own alias indexing).

    Args:
        alias: Alias to search for (e.g., "Cozy Bear", "NOBELIUM").
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include group descriptions.
        remove_revoked_deprecated: Whether to exclude revoked/deprecated groups (default: True).

    Returns:
        {
          "count": <number>,
          "groups": [
            {
              "attack_id": "GXXXX",
              "name": "<group name>",
              "aliases": [...],
              "stix_id": "<intrusion-set--UUID>",
              "description": "<text or null>"
            },
            ...
          ],
          "formatted": "<formatted list>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)
    alias_norm = (alias or "").strip().lower()

    raw_groups: List[Any] = []
    if alias_norm:
        try:
            all_groups = attack_data.get_groups(
                remove_revoked_deprecated=remove_revoked_deprecated
            ) or []
            raw_groups = [
                g for g in all_groups
                if alias_norm == (_stix_get(g, "name", "") or "").strip().lower()
                or any(
                    alias_norm == (a or "").strip().lower()
                    for a in (_stix_get(g, "aliases", []) or [])
                )
            ]
            raw_groups.sort(
                key=lambda g: (
                    (_stix_get(g, "name", "") or "").lower(),
                    str(_stix_get(g, "id", "") or ""),
                )
            )
        except Exception:
            raw_groups = []

    if not raw_groups:
        return {
            "count": 0,
            "groups": [],
            "formatted": "",
            "message": (
                f"No groups found with alias '{alias}' in domain '{domain}'."
            ),
        }

    groups_structured = []
    for grp in raw_groups:
        if isinstance(grp, dict):
            name = grp.get("name")
            stix_id = grp.get("id")
            aliases = grp.get("aliases", [])
            description = grp.get("description") if include_description else None
        else:
            name = getattr(grp, "name", None)
            stix_id = getattr(grp, "id", None)
            aliases = getattr(grp, "aliases", [])
            description = getattr(grp, "description", None) if include_description else None

        # Resolve ATT&CK external ID (GXXXX)
        try:
            attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            attack_id = None

        groups_structured.append(
            {
                "attack_id": attack_id,
                "name": name,
                "aliases": aliases,
                "stix_id": stix_id,
                "description": description,
            }
        )

    # Use your global formatting helper
    formatted = format_objects(
        raw_groups,
        include_description=include_description,
        domain=domain,
    )

    return {
        "count": len(groups_structured),
        "groups": groups_structured,
        "formatted": formatted,
        "message": (
            f"Found {len(groups_structured)} group(s) with alias '{alias}' "
            f"in domain '{domain}'."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_techniques_used_by_group(
    group_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
    limit: PageLimit = DEFAULT_PAGE_LIMIT,
    offset: PageOffset = 0,
    include_formatted: bool = True,
    include_relationships: bool = True,
    attribution_filter: AttributionFilter = "all",
) -> Dict[str, Any]:
    """
    Get all techniques used by a specific APT group, identified by its STIX ID or ATT&CK ID,
    with deterministic attack_id sorting, pagination, and attribution provenance.

    This is similar to `get_group_techniques`, and accepts either the group's STIX UUID
    (e.g. "intrusion-set--...") or its ATT&CK ID (e.g. "G0016").

    Args:
        group_stix_id: STIX ID (intrusion-set--UUID) or ATT&CK ID (e.g., "G0016") of the group.
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include technique descriptions.
        limit: Maximum number of techniques to return per page (1-200).
        offset: Zero-based starting index for pagination (>= 0).
        include_formatted: If False, omits the human-readable formatted block to save tokens.
        include_relationships: If False, returns empty relationship arrays per technique to reduce payload size while preserving attribution_source.
        attribution_filter: Filter by attribution provenance ('all', 'direct', or 'campaign').

    Returns:
        {
          "found": bool,
          "group": {
              "attack_id": "GXXXX" | null,
              "name": "<group name or null>",
              "stix_id": "<intrusion-set--UUID>",
              "description": "<text or null>"
          } | null,
          "count": <number of techniques in this page>,
          "total_count": <total number of techniques>,
          "offset": <page offset>,
          "limit": <page limit>,
          "has_more": bool,
          "next_offset": int | null,
          "techniques": [
            {
              "attack_id": "TXXXX or TXXXX.YYY" | null,
              "name": "<technique name>",
              "stix_id": "<attack-pattern--UUID>",
              "description": "<text or null>",
              "attribution_source": "direct" | "campaign" | "both",
              "relationships": [
                {
                  "stix_id": "<relationship--UUID>",
                  "relationship_type": "uses",
                  "description": "<relationship description or null>",
                  "source_ref": "<source STIX ID>",
                  "target_ref": "<target STIX ID>"
                },
                ...
              ]
            },
            ...
          ],
          "formatted": "<human-readable technique list>",
          "message": "<status summary>"
        }
    """
    safe_limit, safe_offset = _validate_pagination(limit, offset)
    safe_attr_filter = _validate_attribution_filter(attribution_filter)
    attack_data = get_attack_data(domain)

    resolved_id, grp_obj, err = _resolve_stix_object(
        group_stix_id, domain=domain, expected_stix_type="intrusion-set"
    )
    if resolved_id is None:
        return {
            "found": False,
            "group": None,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "techniques": [],
            "formatted": "",
            "message": err or f"Group '{group_stix_id}' not found in domain '{domain}'.",
        }
    group_stix_id = resolved_id

    group_info: Optional[Dict[str, Any]] = None
    if grp_obj is not None:
        g_name = _stix_get(grp_obj, "name")
        g_desc = _stix_get(grp_obj, "description") if include_description else None
        try:
            g_attack_id = attack_data.get_attack_id(group_stix_id)
        except Exception:
            g_attack_id = None

        group_info = {
            "attack_id": g_attack_id,
            "name": g_name,
            "stix_id": group_stix_id,
            "description": g_desc,
        }

    # Fetch techniques used by this group
    try:
        rel_entries = attack_data.get_techniques_used_by_group(group_stix_id)
    except Exception:
        rel_entries = []

    if not rel_entries:
        return {
            "found": True,
            "group": group_info,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "techniques": [],
            "formatted": "",
            "message": (
                f"No techniques found for group STIX ID '{group_stix_id}' "
                f"in domain '{domain}'."
            ),
        }

    normalized_entries: List[Tuple[Tuple[int, str, str, str], Any, Optional[str], Optional[str], Optional[str], str, List[Dict[str, Any]]]] = []

    for entry in rel_entries:
        if isinstance(entry, dict) and "object" in entry:
            tech_obj = entry.get("object")
            rels = entry.get("relationships", [])
        elif hasattr(entry, "object"):
            tech_obj = getattr(entry, "object", None)
            rels = getattr(entry, "relationships", [])
        else:
            tech_obj = entry
            rels = []

        if tech_obj is None:
            continue

        relationships_info = [_format_rel_edge(r, include_description=include_description) for r in rels]
        attribution_source = _classify_group_technique_attribution(relationships_info, group_stix_id)
        if not _matches_attribution_filter(attribution_source, safe_attr_filter):
            continue

        t_name = _stix_get(tech_obj, "name")
        t_stix_id = _stix_get(tech_obj, "id")
        try:
            t_attack_id = attack_data.get_attack_id(t_stix_id) if t_stix_id else None
        except Exception:
            t_attack_id = None

        normalized_entries.append(
            (
                _attack_id_sort_key(t_attack_id, t_name, t_stix_id),
                tech_obj,
                t_attack_id,
                t_name,
                t_stix_id,
                attribution_source,
                relationships_info if include_relationships else [],
            )
        )

    normalized_entries.sort(key=lambda item: item[0])
    page_entries, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        normalized_entries, limit=limit, offset=offset
    )

    techniques_structured: List[Dict[str, Any]] = []
    technique_objects_for_format: List[Any] = []

    for _sort_key, tech_obj, t_attack_id, t_name, t_stix_id, attribution_source, relationships_info in page_entries:
        technique_objects_for_format.append(tech_obj)
        t_desc = _stix_get(tech_obj, "description") if include_description else None

        techniques_structured.append(
            {
                "attack_id": t_attack_id,
                "name": t_name,
                "stix_id": t_stix_id,
                "description": t_desc,
                "attribution_source": attribution_source,
                "relationships": relationships_info,
            }
        )

    formatted = ""
    if include_formatted and technique_objects_for_format:
        formatted = format_objects(
            technique_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "found": True,
        "group": group_info,
        "count": len(techniques_structured),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": next_offset,
        "techniques": techniques_structured,
        "formatted": formatted,
        "message": (
            f"Found {total_count} technique(s) for group STIX ID "
            f"'{group_stix_id}' in domain '{domain}' "
            f"(returning {len(techniques_structured)} at offset {safe_offset})."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_software_used_by_group(
    group_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
    limit: PageLimit = DEFAULT_PAGE_LIMIT,
    offset: PageOffset = 0,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Get all software (malware and tools) used by a specific APT group,
    identified by its STIX ID or ATT&CK ID (e.g., "G0016"), with pagination.

    This uses MITRE's `get_software_used_by_group` to follow 'uses'
    relationships from an intrusion set (group) to software objects, sorted
    deterministically by attack_id ascending.

    Args:
        group_stix_id: STIX ID (e.g., "intrusion-set--UUID") or ATT&CK ID (e.g., "G0016").
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include software descriptions.
        limit: Maximum number of software items to return per page (1-200).
        offset: Zero-based starting index for pagination (>= 0).
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
          "found": bool,
          "group": {
              "attack_id": "GXXXX" | null,
              "name": "<group name or null>",
              "stix_id": "<intrusion-set--UUID>",
              "description": "<text or null>"
          } | null,
          "count": <number of software objects in this page>,
          "total_count": <total number of software objects>,
          "offset": <page offset>,
          "limit": <page limit>,
          "has_more": bool,
          "next_offset": int | null,
          "software": [
            {
              "attack_id": "SXXXX or similar" | null,
              "name": "<software name>",
              "aliases": [...],
              "stix_id": "<STIX ID>",
              "type": "<malware|tool|...>",
              "description": "<text or null>",
              "relationships": [
                {
                  "stix_id": "<relationship--UUID>",
                  "relationship_type": "uses",
                  "description": "<relationship description or null>",
                  "source_ref": "<source STIX ID>",
                  "target_ref": "<target STIX ID>",
                },
                ...
              ]
            },
            ...
          ],
          "formatted": "<human-readable list of software>",
          "message": "<status summary>"
        }
    """
    safe_limit, safe_offset = _validate_pagination(limit, offset)
    attack_data = get_attack_data(domain)

    resolved_id, grp_obj, err = _resolve_stix_object(
        group_stix_id, domain=domain, expected_stix_type="intrusion-set"
    )
    if resolved_id is None:
        return {
            "found": False,
            "group": None,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "software": [],
            "formatted": "",
            "message": err or f"Group '{group_stix_id}' not found in domain '{domain}'.",
        }
    group_stix_id = resolved_id

    group_info: Optional[Dict[str, Any]] = None
    if grp_obj is not None:
        g_name = _stix_get(grp_obj, "name")
        g_desc = _stix_get(grp_obj, "description") if include_description else None
        try:
            g_attack_id = attack_data.get_attack_id(group_stix_id)
        except Exception:
            g_attack_id = None

        group_info = {
            "attack_id": g_attack_id,
            "name": g_name,
            "stix_id": group_stix_id,
            "description": g_desc,
        }

    # Get software used by this group
    try:
        rel_entries = attack_data.get_software_used_by_group(group_stix_id)
    except Exception:
        rel_entries = []

    if not rel_entries:
        return {
            "found": True,
            "group": group_info,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "software": [],
            "formatted": "",
            "message": (
                f"No software found for group STIX ID '{group_stix_id}' "
                f"in domain '{domain}'."
            ),
        }

    normalized_entries: List[Tuple[Tuple[int, str, str, str], Any, Optional[str], Optional[str], Optional[str], List[Any]]] = []

    for entry in rel_entries:
        if isinstance(entry, dict):
            sw_obj = entry.get("object")
            rels = entry.get("relationships", [])
        else:
            sw_obj = getattr(entry, "object", None)
            rels = getattr(entry, "relationships", [])

        if sw_obj is None:
            continue

        s_name = _stix_get(sw_obj, "name")
        s_stix_id = _stix_get(sw_obj, "id")
        try:
            s_attack_id = attack_data.get_attack_id(s_stix_id) if s_stix_id else None
        except Exception:
            s_attack_id = None

        normalized_entries.append(
            (_attack_id_sort_key(s_attack_id, s_name, s_stix_id), sw_obj, s_attack_id, s_name, s_stix_id, rels)
        )

    normalized_entries.sort(key=lambda item: item[0])
    page_entries, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        normalized_entries, limit=limit, offset=offset
    )

    software_structured: List[Dict[str, Any]] = []
    software_objects_for_format: List[Any] = []

    for _sort_key, sw_obj, s_attack_id, s_name, s_stix_id, rels in page_entries:
        software_objects_for_format.append(sw_obj)
        s_type = _stix_get(sw_obj, "type")
        s_aliases = _get_aliases(sw_obj)
        s_desc = _stix_get(sw_obj, "description") if include_description else None
        relationships_info = [_format_rel_edge(r, include_description=include_description) for r in rels]

        software_structured.append(
            {
                "attack_id": s_attack_id,
                "name": s_name,
                "aliases": s_aliases,
                "stix_id": s_stix_id,
                "type": s_type,
                "description": s_desc,
                "relationships": relationships_info,
            }
        )

    formatted = ""
    if include_formatted and software_objects_for_format:
        formatted = format_objects(
            software_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "found": True,
        "group": group_info,
        "count": len(software_structured),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": next_offset,
        "software": software_structured,
        "formatted": formatted,
        "message": (
            f"Found {total_count} software object(s) used by group "
            f"STIX ID '{group_stix_id}' in domain '{domain}' "
            f"(returning {len(software_structured)} at offset {safe_offset})."
        ),
    }


# ---------------------------------------------------------------------------
# Campaign lookup
# ---------------------------------------------------------------------------

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_campaigns_attributed_to_group(
    group_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Get all campaigns attributed to a specific intrusion set (APT group),
    identified by its STIX ID or ATT&CK ID (e.g., "G0016").

    Campaigns represent specific operations or intrusion events attributed
    to a threat group.

    Args:
        group_stix_id: STIX UUID (e.g., "intrusion-set--UUID") or ATT&CK ID (e.g., "G0016").
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include campaign descriptions.
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
          "found": bool,
          "group": {
              "attack_id": "GXXXX" | null,
              "name": "<group name or null>",
              "stix_id": "<intrusion-set--UUID>",
              "description": "<text or null>"
          } | null,

          "count": <number of campaigns>,

          "campaigns": [
            {
              "attack_id": "CXXXX" | null,
              "name": "<campaign name>",
              "aliases": [...],
              "stix_id": "<campaign--UUID>",
              "description": "<text or null>"
            },
            ...
          ],

          "formatted": "<formatted human-readable block>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)

    resolved_id, grp_obj, err = _resolve_stix_object(
        group_stix_id, domain=domain, expected_stix_type="intrusion-set"
    )
    if resolved_id is None:
        return {
            "found": False,
            "group": None,
            "count": 0,
            "campaigns": [],
            "formatted": "",
            "message": err or f"Group '{group_stix_id}' not found in domain '{domain}'.",
        }
    group_stix_id = resolved_id

    group_info = None
    if grp_obj is not None:
        g_name = _stix_get(grp_obj, "name")
        g_desc = _stix_get(grp_obj, "description") if include_description else None
        try:
            g_attack_id = attack_data.get_attack_id(group_stix_id)
        except Exception:
            g_attack_id = None

        group_info = {
            "attack_id": g_attack_id,
            "name": g_name,
            "stix_id": group_stix_id,
            "description": g_desc,
        }

    # Retrieve campaigns for this group
    try:
        campaign_entries = attack_data.get_campaigns_attributed_to_group(group_stix_id)
    except Exception:
        campaign_entries = []

    if not campaign_entries:
        return {
            "found": True,
            "group": group_info,
            "count": 0,
            "campaigns": [],
            "formatted": "",
            "message": (
                f"No campaigns attributed to group STIX ID '{group_stix_id}' "
                f"in domain '{domain}'."
            ),
        }

    structured_campaigns = []
    campaign_objects_for_format = []

    for item in campaign_entries:
        c = _unwrap_stix_object(item)
        if c is None:
            continue
        name = _stix_get(c, "name")
        stix_id = _stix_get(c, "id")
        aliases = _get_aliases(c)
        desc = _stix_get(c, "description") if include_description else None

        campaign_objects_for_format.append(c)

        try:
            attack_id = attack_data.get_attack_id(stix_id) if stix_id else None
        except Exception:
            attack_id = None

        structured_campaigns.append(
            {
                "attack_id": attack_id,
                "name": name,
                "aliases": aliases,
                "stix_id": stix_id,
                "description": desc,
            }
        )

    formatted = (
        format_objects(
            campaign_objects_for_format,
            include_description=include_description,
            domain=domain,
        )
        if include_formatted
        else ""
    )

    return {
        "found": True,
        "group": group_info,
        "count": len(structured_campaigns),
        "campaigns": structured_campaigns,
        "formatted": formatted,
        "message": (
            f"Found {len(structured_campaigns)} campaign(s) attributed to group "
            f"STIX ID '{group_stix_id}' in domain '{domain}'."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_campaigns_by_alias(
    alias: str,
    domain: str = "enterprise",
    include_description: bool = True,
    remove_revoked_deprecated: bool = True,
) -> Dict[str, Any]:
    """
    Get campaigns by their alias.

    Campaigns frequently have multiple names assigned by different vendors
    or research teams. This function resolves those aliases.

    Args:
        alias: Campaign alias or alternate name (case-insensitive)
        domain: ATT&CK domain ("enterprise", "ics", etc.)
        include_description: Include campaign descriptions in output
        remove_revoked_deprecated: Whether to exclude revoked/deprecated campaigns (default: True).

    Returns:
        {
          "alias": "<requested name>",
          "count": int,
          "campaigns": [
            {
              "name": "...",
              "stix_id": "<campaign--UUID>",
              "attack_id": "Cxxxx" | null,
              "description": "..." | null
            },
            ...
          ],
          "formatted": "<multi-line readable text>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)
    alias_norm = (alias or "").strip().lower()

    # Exact case-insensitive match against campaign name and aliases
    campaigns: List[Any] = []
    if alias_norm:
        try:
            all_campaigns = attack_data.get_campaigns(
                remove_revoked_deprecated=remove_revoked_deprecated
            ) or []
            campaigns = [
                c for c in all_campaigns
                if alias_norm == (_stix_get(c, "name", "") or "").strip().lower()
                or any(
                    alias_norm == (a or "").strip().lower()
                    for a in (_stix_get(c, "aliases") or _stix_get(c, "x_mitre_aliases") or [])
                )
            ]
            campaigns.sort(
                key=lambda c: (
                    (_stix_get(c, "name", "") or "").lower(),
                    str(_stix_get(c, "id", "") or ""),
                )
            )
        except Exception:
            campaigns = []

    if not campaigns:
        return {
            "alias": alias,
            "count": 0,
            "campaigns": [],
            "formatted": "",
            "message": f"No campaigns found with alias '{alias}' in domain '{domain}'.",
        }

    # Build structured campaign entries
    campaign_entries = []
    for c in campaigns:
        name = _stix_get(c, "name")
        stix_id = _stix_get(c, "id")
        aliases = _stix_get(c, "aliases") or _stix_get(c, "x_mitre_aliases") or []

        try:
            attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            attack_id = None

        description = _stix_get(c, "description") if include_description else None

        campaign_entries.append(
            {
                "name": name,
                "aliases": aliases,
                "stix_id": stix_id,
                "attack_id": attack_id,
                "description": description,
            }
        )

    # Human-friendly formatted text
    formatted = format_objects(
        campaigns,
        include_description=include_description,
        domain=domain,
    )

    return {
        "alias": alias,
        "count": len(campaign_entries),
        "campaigns": campaign_entries,
        "formatted": formatted,
        "message": (
            f"Found {len(campaign_entries)} campaign(s) matching alias '{alias}' "
            f"in domain '{domain}'."
        ),
    }


@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_techniques_used_by_group_software(
    group_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
    limit: PageLimit = DEFAULT_PAGE_LIMIT,
    offset: PageOffset = 0,
    include_formatted: bool = True,
    include_relationships: bool = True,
) -> Dict[str, Any]:
    """
    Get techniques used by the software that a group uses (Group → Software → Techniques),
    sorted deterministically by attack_id ascending with pagination.

    This provides an indirect view of a group's capabilities by following:
        Group (intrusion set) → Software (malware/tools) → Techniques

    Accepts either a STIX ID ("intrusion-set--UUID") or an ATT&CK ID (e.g., "G0016").

    Args:
        group_stix_id: STIX ID ("intrusion-set--UUID") or ATT&CK ID (e.g., "G0016").
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include technique descriptions.
        limit: Maximum number of techniques to return per page (1-200).
        offset: Zero-based starting index for pagination (>= 0).
        include_formatted: If False, omits the human-readable formatted block to save tokens.
        include_relationships: If False, returns empty relationships and provenance_paths arrays per technique to reduce payload size.

    Returns:
        {
          "found": bool,
          "group": {
              "attack_id": "GXXXX" | null,
              "name": "<group name or null>",
              "stix_id": "<intrusion-set--UUID>",
              "description": "<text or null>",
          } | null,

          "count": <number of techniques in this page>,
          "total_count": <total number of techniques>,
          "offset": <page offset>,
          "limit": <page limit>,
          "has_more": bool,
          "next_offset": int | null,

          "techniques": [
            {
              "attack_id": "TXXXX or TXXXX.YYY" | null,
              "name": "<technique name>",
              "stix_id": "<attack-pattern--UUID>",
              "description": "<text or null>",
              "relationships": [
                {
                  "stix_id": "<relationship--UUID>",
                  "relationship_type": "uses",
                  "description": "<relationship description or null>",
                  "source_ref": "<source STIX ID>",
                  "target_ref": "<target STIX ID>",
                },
                ...
              ]
            },
            ...
          ],

          "formatted": "<human-readable list of techniques>",
          "message": "<status summary>"
        }
    """
    safe_limit, safe_offset = _validate_pagination(limit, offset)
    attack_data = get_attack_data(domain)

    resolved_id, grp_obj, err = _resolve_stix_object(
        group_stix_id, domain=domain, expected_stix_type="intrusion-set"
    )
    if resolved_id is None:
        return {
            "found": False,
            "group": None,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "techniques": [],
            "formatted": "",
            "message": err or f"Group '{group_stix_id}' not found in domain '{domain}'.",
        }
    group_stix_id = resolved_id

    group_info: Optional[Dict[str, Any]] = None
    if grp_obj is not None:
        g_name = _stix_get(grp_obj, "name")
        g_desc = _stix_get(grp_obj, "description") if include_description else None
        try:
            g_attack_id = attack_data.get_attack_id(group_stix_id)
        except Exception:
            g_attack_id = None

        group_info = {
            "attack_id": g_attack_id,
            "name": g_name,
            "stix_id": group_stix_id,
            "description": g_desc,
        }

    # Traverse Group -> Software -> Technique so both hops' STIX relationships
    # are preserved as verifiable provenance paths.
    try:
        sw_entries = attack_data.get_software_used_by_group(group_stix_id) or []
    except Exception:
        sw_entries = []

    tech_by_id: Dict[str, Any] = {}
    tech_paths: Dict[str, List[Dict[str, Any]]] = {}
    tech_rels_by_id: Dict[str, Dict[str, Dict[str, Any]]] = {}

    for sw_entry in sw_entries:
        if isinstance(sw_entry, dict) and "object" in sw_entry:
            sw_obj = sw_entry.get("object")
            g2s_rels = sw_entry.get("relationships", []) or []
        elif hasattr(sw_entry, "object"):
            sw_obj = getattr(sw_entry, "object", None)
            g2s_rels = getattr(sw_entry, "relationships", []) or []
        else:
            sw_obj = sw_entry
            g2s_rels = []

        if sw_obj is None:
            continue

        sw_obj = _unwrap_stix_object(sw_obj)
        sw_stix_id = _stix_get(sw_obj, "id")
        if not sw_stix_id:
            continue

        sw_name = _stix_get(sw_obj, "name")
        sw_type = _stix_get(sw_obj, "type")
        try:
            sw_attack_id = attack_data.get_attack_id(sw_stix_id)
        except Exception:
            sw_attack_id = None

        sw_info = {
            "attack_id": sw_attack_id,
            "name": sw_name,
            "stix_id": sw_stix_id,
            "type": sw_type,
        }

        try:
            sw_tech_entries = attack_data.get_techniques_used_by_software(sw_stix_id) or []
        except Exception:
            sw_tech_entries = []

        for t_entry in sw_tech_entries:
            if isinstance(t_entry, dict) and "object" in t_entry:
                t_obj = t_entry.get("object")
                s2t_rels = t_entry.get("relationships", []) or []
            elif hasattr(t_entry, "object"):
                t_obj = getattr(t_entry, "object", None)
                s2t_rels = getattr(t_entry, "relationships", []) or []
            else:
                t_obj = t_entry
                s2t_rels = []

            if t_obj is None:
                continue

            t_obj = _unwrap_stix_object(t_obj)
            t_stix_id = _stix_get(t_obj, "id")
            if not t_stix_id:
                continue

            tech_by_id.setdefault(t_stix_id, t_obj)
            paths_list = tech_paths.setdefault(t_stix_id, [])
            rel_map = tech_rels_by_id.setdefault(t_stix_id, {})

            g2s_formatted = [_format_rel_edge(r, include_description=include_description) for r in g2s_rels]
            s2t_formatted = [_format_rel_edge(r, include_description=include_description) for r in s2t_rels]

            direct_g2s = [
                r
                for r in g2s_formatted
                if r.get("relationship_type") == "uses"
                and r.get("source_ref") == group_stix_id
                and r.get("target_ref") == sw_stix_id
            ]
            direct_s2t = [
                r
                for r in s2t_formatted
                if r.get("relationship_type") == "uses"
                and r.get("source_ref") == sw_stix_id
                and r.get("target_ref") == t_stix_id
            ]

            camp_attr_by_id: Dict[str, List[Dict[str, Any]]] = {}
            camp_uses_by_id: Dict[str, List[Dict[str, Any]]] = {}
            for r in g2s_formatted:
                src = str(r.get("source_ref") or "")
                if not src.startswith("campaign--"):
                    continue
                if r.get("relationship_type") == "attributed-to" and r.get("target_ref") == group_stix_id:
                    camp_attr_by_id.setdefault(src, []).append(r)
                elif r.get("relationship_type") == "uses" and r.get("target_ref") == sw_stix_id:
                    camp_uses_by_id.setdefault(src, []).append(r)

            campaign_hops: List[Tuple[str, Dict[str, Any], Dict[str, Any]]] = []
            for camp_id in sorted(set(camp_attr_by_id) & set(camp_uses_by_id)):
                for attr_edge in camp_attr_by_id[camp_id]:
                    for c2s_edge in camp_uses_by_id[camp_id]:
                        campaign_hops.append((camp_id, attr_edge, c2s_edge))

            # Only record authentic direct 'uses' edges in top-level relationships;
            # campaign-mediated links are recorded explicitly as indirect provenance paths.
            for r_edge in direct_g2s + direct_s2t:
                r_key = r_edge.get("stix_id") or (
                    f"{r_edge.get('source_ref')}->{r_edge.get('relationship_type')}->{r_edge.get('target_ref')}"
                )
                rel_map.setdefault(r_key, r_edge)

            for s2t_edge in direct_s2t or [None]:
                for g2s_edge in direct_g2s:
                    paths_list.append(
                        {
                            "path_type": "direct",
                            "software": sw_info,
                            "group_uses_software": g2s_edge,
                            "software_uses_technique": s2t_edge,
                        }
                    )
                for camp_id, attr_edge, c2s_edge in campaign_hops:
                    paths_list.append(
                        {
                            "path_type": "indirect_via_campaign",
                            "software": sw_info,
                            "campaign_stix_id": camp_id,
                            "campaign_attributed_to_group": attr_edge,
                            "campaign_uses_software": c2s_edge,
                            "software_uses_technique": s2t_edge,
                        }
                    )
                if not direct_g2s and not campaign_hops:
                    paths_list.append(
                        {
                            "path_type": "indirect_unverified",
                            "software": sw_info,
                            "software_uses_technique": s2t_edge,
                        }
                    )

    if not tech_by_id:
        return {
            "found": True,
            "group": group_info,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "techniques": [],
            "formatted": "",
            "message": (
                f"No techniques found via software used by group STIX ID "
                f"'{group_stix_id}' in domain '{domain}'."
            ),
        }

    normalized_techs: List[Tuple[Tuple[int, str, str, str], str, Any, Optional[str], Optional[str]]] = []
    for t_stix_id, tech_obj in tech_by_id.items():
        t_name = _stix_get(tech_obj, "name")
        try:
            t_attack_id = attack_data.get_attack_id(t_stix_id)
        except Exception:
            t_attack_id = None
        normalized_techs.append(
            (_attack_id_sort_key(t_attack_id, t_name, t_stix_id), t_stix_id, tech_obj, t_attack_id, t_name)
        )

    normalized_techs.sort(key=lambda item: item[0])
    page_techs, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        normalized_techs, limit=limit, offset=offset
    )

    techniques_structured: List[Dict[str, Any]] = []
    technique_objects_for_format: List[Any] = []

    for _sort_key, t_stix_id, tech_obj, t_attack_id, t_name in page_techs:
        technique_objects_for_format.append(tech_obj)

        t_desc = _stix_get(tech_obj, "description") if include_description else None

        paths_sorted = sorted(
            tech_paths.get(t_stix_id, []),
            key=lambda p: (
                str(p.get("path_type") or ""),
                str((p.get("software") or {}).get("stix_id") or ""),
                str((p.get("group_uses_software") or {}).get("stix_id") or ""),
                str(p.get("campaign_stix_id") or ""),
                str((p.get("campaign_uses_software") or {}).get("stix_id") or ""),
                str((p.get("software_uses_technique") or {}).get("stix_id") or ""),
            ),
        )
        rels_sorted = [
            tech_rels_by_id[t_stix_id][k]
            for k in sorted(tech_rels_by_id.get(t_stix_id, {}).keys())
        ]

        techniques_structured.append(
            {
                "attack_id": t_attack_id,
                "name": t_name,
                "stix_id": t_stix_id,
                "description": t_desc,
                "relationships": rels_sorted if include_relationships else [],
                "provenance_paths": paths_sorted if include_relationships else [],
            }
        )

    formatted = ""
    if include_formatted and technique_objects_for_format:
        formatted = format_objects(
            technique_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "found": True,
        "group": group_info,
        "count": len(techniques_structured),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": next_offset,
        "techniques": techniques_structured,
        "formatted": formatted,
        "message": (
            f"Found {total_count} technique(s) reachable via software "
            f"used by group STIX ID '{group_stix_id}' in domain '{domain}' "
            f"(returning {len(techniques_structured)} at offset {safe_offset})."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_groups_using_technique(
    technique_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
    limit: PageLimit = DEFAULT_PAGE_LIMIT,
    offset: PageOffset = 0,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Get all APT groups (intrusion sets) that use a specific technique, with pagination.

    This is a reverse lookup: Technique → Groups, sorted deterministically by attack_id ascending.
    Accepts either a STIX ID (e.g., "attack-pattern--UUID") or an ATT&CK ID (e.g., "T1190").

    Args:
        technique_stix_id: STIX ID ("attack-pattern--UUID") or ATT&CK ID (e.g., "T1190").
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include group descriptions.
        limit: Maximum number of groups to return per page (1-200).
        offset: Zero-based starting index for pagination (>= 0).
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
          "found": bool,
          "technique": {
              "attack_id": "TXXXX or TXXXX.YYY" | null,
              "name": "<technique name or null>",
              "stix_id": "<attack-pattern--UUID>",
              "description": "<text or null>",
          } | null,

          "count": <number of groups in this page>,
          "total_count": <total number of groups>,
          "offset": <page offset>,
          "limit": <page limit>,
          "has_more": bool,
          "next_offset": int | null,

          "groups": [
            {
              "attack_id": "GXXXX" | null,
              "name": "<group name>",
              "aliases": [...],
              "stix_id": "<intrusion-set--UUID>",
              "description": "<text or null>",
              "relationships": [
                {
                  "stix_id": "<relationship--UUID>",
                  "relationship_type": "uses",
                  "description": "<relationship description or null>",
                  "source_ref": "<source STIX ID>",
                  "target_ref": "<target STIX ID>",
                },
                ...
              ]
            },
            ...
          ],

          "formatted": "<human-readable list of groups>",
          "message": "<status summary>"
        }
    """
    safe_limit, safe_offset = _validate_pagination(limit, offset)
    attack_data = get_attack_data(domain)

    resolved_id, tech_obj, err = _resolve_stix_object(
        technique_stix_id, domain=domain, expected_stix_type="attack-pattern"
    )
    if resolved_id is None:
        return {
            "found": False,
            "technique": None,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "groups": [],
            "formatted": "",
            "message": err or f"Technique '{technique_stix_id}' not found in domain '{domain}'.",
        }
    technique_stix_id = resolved_id

    technique_info: Optional[Dict[str, Any]] = None
    if tech_obj is not None:
        t_name = _stix_get(tech_obj, "name")
        t_desc = _stix_get(tech_obj, "description") if include_description else None
        try:
            t_attack_id = attack_data.get_attack_id(technique_stix_id)
        except Exception:
            t_attack_id = None

        technique_info = {
            "attack_id": t_attack_id,
            "name": t_name,
            "stix_id": technique_stix_id,
            "description": t_desc,
        }

    # Get groups that use this technique
    try:
        rel_entries = attack_data.get_groups_using_technique(technique_stix_id)
    except Exception:
        rel_entries = []

    if not rel_entries:
        return {
            "found": True,
            "technique": technique_info,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "groups": [],
            "formatted": "",
            "message": (
                f"No groups found using technique STIX ID '{technique_stix_id}' "
                f"in domain '{domain}'."
            ),
        }

    normalized_entries: List[Tuple[Tuple[int, str, str, str], Any, Optional[str], Optional[str], Optional[str], List[Any]]] = []

    for entry in rel_entries:
        if isinstance(entry, dict) and ("object" in entry or "relationships" in entry):
            grp_obj = entry.get("object", entry)
            rels = entry.get("relationships", [])
        else:
            grp_obj = entry
            rels = []

        if grp_obj is None:
            continue

        g_name = _stix_get(grp_obj, "name")
        g_stix_id = _stix_get(grp_obj, "id")
        try:
            g_attack_id = attack_data.get_attack_id(g_stix_id) if g_stix_id else None
        except Exception:
            g_attack_id = None

        normalized_entries.append(
            (_attack_id_sort_key(g_attack_id, g_name, g_stix_id), grp_obj, g_attack_id, g_name, g_stix_id, rels)
        )

    normalized_entries.sort(key=lambda item: item[0])
    page_entries, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        normalized_entries, limit=limit, offset=offset
    )

    groups_structured: List[Dict[str, Any]] = []
    group_objects_for_format: List[Any] = []

    for _sort_key, grp_obj, g_attack_id, g_name, g_stix_id, rels in page_entries:
        group_objects_for_format.append(grp_obj)
        g_aliases = _get_aliases(grp_obj)
        g_desc = _stix_get(grp_obj, "description") if include_description else None
        relationships_info = [_format_rel_edge(r, include_description=include_description) for r in rels]

        groups_structured.append(
            {
                "attack_id": g_attack_id,
                "name": g_name,
                "aliases": g_aliases,
                "stix_id": g_stix_id,
                "description": g_desc,
                "relationships": relationships_info,
            }
        )

    formatted = ""
    if include_formatted and group_objects_for_format:
        formatted = format_objects(
            group_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "found": True,
        "technique": technique_info,
        "count": len(groups_structured),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": next_offset,
        "groups": groups_structured,
        "formatted": formatted,
        "message": (
            f"Found {total_count} group(s) using technique STIX ID "
            f"'{technique_stix_id}' in domain '{domain}' "
            f"(returning {len(groups_structured)} at offset {safe_offset})."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_groups_using_software(
    software_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
    limit: PageLimit = DEFAULT_PAGE_LIMIT,
    offset: PageOffset = 0,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Get all APT groups (intrusion sets) that use a specific software/malware, with pagination.

    This is a reverse lookup: Software → Groups, sorted deterministically by attack_id ascending.
    Accepts either a STIX ID ("malware--UUID" / "tool--UUID") or an ATT&CK ID (e.g., "S0154").

    Args:
        software_stix_id: STIX ID ("malware--UUID", "tool--UUID") or ATT&CK ID (e.g., "S0154").
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include group descriptions.
        limit: Maximum number of groups to return per page (1-200).
        offset: Zero-based starting index for pagination (>= 0).
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
          "found": bool,
          "software": {
              "attack_id": "SXXXX or similar" | null,
              "name": "<software name or null>",
              "stix_id": "<software STIX ID>",
              "type": "<tool|malware|...> or null",
              "description": "<text or null>",
          } | null,

          "count": <number of groups in this page>,
          "total_count": <total number of groups>,
          "offset": <page offset>,
          "limit": <page limit>,
          "has_more": bool,
          "next_offset": int | null,

          "groups": [
            {
              "attack_id": "GXXXX" | null,
              "name": "<group name>",
              "aliases": [...],
              "stix_id": "<intrusion-set--UUID>",
              "description": "<text or null>",
              "relationships": [
                {
                  "stix_id": "<relationship--UUID>",
                  "relationship_type": "uses",
                  "description": "<relationship description or null>",
                  "source_ref": "<source STIX ID>",
                  "target_ref": "<target STIX ID>",
                },
                ...
              ]
            },
            ...
          ],

          "formatted": "<human-readable list of groups>",
          "message": "<status summary>"
        }
    """
    safe_limit, safe_offset = _validate_pagination(limit, offset)
    attack_data = get_attack_data(domain)

    resolved_id, sw_obj, err = _resolve_stix_object(
        software_stix_id, domain=domain, expected_stix_type=("malware", "tool")
    )
    if resolved_id is None:
        return {
            "found": False,
            "software": None,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "groups": [],
            "formatted": "",
            "message": err or f"Software '{software_stix_id}' not found in domain '{domain}'.",
        }
    software_stix_id = resolved_id

    software_info: Optional[Dict[str, Any]] = None
    if sw_obj is not None:
        s_name = _stix_get(sw_obj, "name")
        s_type = _stix_get(sw_obj, "type")
        s_desc = _stix_get(sw_obj, "description") if include_description else None
        try:
            s_attack_id = attack_data.get_attack_id(software_stix_id)
        except Exception:
            s_attack_id = None

        software_info = {
            "attack_id": s_attack_id,
            "name": s_name,
            "stix_id": software_stix_id,
            "type": s_type,
            "description": s_desc,
        }

    # Get groups that use this software
    try:
        rel_entries = attack_data.get_groups_using_software(software_stix_id)
    except Exception:
        rel_entries = []

    if not rel_entries:
        return {
            "found": True,
            "software": software_info,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "groups": [],
            "formatted": "",
            "message": (
                f"No groups found using software STIX ID '{software_stix_id}' "
                f"in domain '{domain}'."
            ),
        }

    normalized_entries: List[Tuple[Tuple[int, str, str, str], Any, Optional[str], Optional[str], Optional[str], List[Any]]] = []

    for entry in rel_entries:
        if isinstance(entry, dict) and ("object" in entry or "relationships" in entry):
            grp_obj = entry.get("object", entry)
            rels = entry.get("relationships", [])
        else:
            grp_obj = entry
            rels = []

        if grp_obj is None:
            continue

        g_name = _stix_get(grp_obj, "name")
        g_stix_id = _stix_get(grp_obj, "id")
        try:
            g_attack_id = attack_data.get_attack_id(g_stix_id) if g_stix_id else None
        except Exception:
            g_attack_id = None

        normalized_entries.append(
            (_attack_id_sort_key(g_attack_id, g_name, g_stix_id), grp_obj, g_attack_id, g_name, g_stix_id, rels)
        )

    normalized_entries.sort(key=lambda item: item[0])
    page_entries, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        normalized_entries, limit=limit, offset=offset
    )

    groups_structured: List[Dict[str, Any]] = []
    group_objects_for_format: List[Any] = []

    for _sort_key, grp_obj, g_attack_id, g_name, g_stix_id, rels in page_entries:
        group_objects_for_format.append(grp_obj)
        g_aliases = _get_aliases(grp_obj)
        g_desc = _stix_get(grp_obj, "description") if include_description else None
        relationships_info = [_format_rel_edge(r, include_description=include_description) for r in rels]

        groups_structured.append(
            {
                "attack_id": g_attack_id,
                "name": g_name,
                "aliases": g_aliases,
                "stix_id": g_stix_id,
                "description": g_desc,
                "relationships": relationships_info,
            }
        )

    formatted = ""
    if include_formatted and group_objects_for_format:
        formatted = format_objects(
            group_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "found": True,
        "software": software_info,
        "count": len(groups_structured),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": next_offset,
        "groups": groups_structured,
        "formatted": formatted,
        "message": (
            f"Found {total_count} group(s) using software STIX ID "
            f"'{software_stix_id}' in domain '{domain}' "
            f"(returning {len(groups_structured)} at offset {safe_offset})."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_groups_attributing_to_campaign(
    campaign_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Get all APT groups (intrusion sets) attributed to a specific campaign.

    This is a reverse lookup: Campaign → Groups.
    Accepts either a STIX ID ("campaign--UUID") or an ATT&CK ID (e.g., "C0024").

    Args:
        campaign_stix_id: STIX ID ("campaign--UUID") or ATT&CK ID (e.g., "C0024").
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include group descriptions.
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
          "found": bool,
          "campaign": {
              "attack_id": "CXXXX" | null,
              "name": "<campaign name or null>",
              "stix_id": "<campaign--UUID>",
              "description": "<text or null>"
          } | null,

          "count": <number of groups>,

          "groups": [
            {
              "attack_id": "GXXXX" | null,
              "name": "<group name>",
              "aliases": [...],
              "stix_id": "<intrusion-set--UUID>",
              "description": "<text or null>",
              "relationships": [
                {
                  "stix_id": "<relationship--UUID>",
                  "relationship_type": "<type>",
                  "description": "<relationship description or null>",
                  "source_ref": "<source STIX ID>",
                  "target_ref": "<target STIX ID>",
                },
                ...
              ]
            },
            ...
          ],

          "formatted": "<human-readable list of groups>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)

    resolved_id, camp_obj, err = _resolve_stix_object(
        campaign_stix_id, domain=domain, expected_stix_type="campaign"
    )
    if resolved_id is None:
        return {
            "found": False,
            "campaign": None,
            "count": 0,
            "groups": [],
            "formatted": "",
            "message": err or f"Campaign '{campaign_stix_id}' not found in domain '{domain}'.",
        }
    campaign_stix_id = resolved_id

    campaign_info: Optional[Dict[str, Any]] = None
    if camp_obj is not None:
        c_name = _stix_get(camp_obj, "name")
        c_desc = _stix_get(camp_obj, "description") if include_description else None
        try:
            c_attack_id = attack_data.get_attack_id(campaign_stix_id)
        except Exception:
            c_attack_id = None

        campaign_info = {
            "attack_id": c_attack_id,
            "name": c_name,
            "stix_id": campaign_stix_id,
            "description": c_desc,
        }

    # Get groups attributed to this campaign
    try:
        rel_entries = attack_data.get_groups_attributing_to_campaign(campaign_stix_id)
    except Exception:
        rel_entries = []

    if not rel_entries:
        return {
            "found": True,
            "campaign": campaign_info,
            "count": 0,
            "groups": [],
            "formatted": "",
            "message": (
                f"No groups found attributing to campaign STIX ID "
                f"'{campaign_stix_id}' in domain '{domain}'."
            ),
        }

    groups_structured: List[Dict[str, Any]] = []
    group_objects_for_format: List[Any] = []

    for entry in rel_entries:
        if isinstance(entry, dict) and ("object" in entry or "relationships" in entry):
            grp_obj = entry.get("object", entry)
            rels = entry.get("relationships", [])
        else:
            grp_obj = entry
            rels = []

        if grp_obj is None:
            continue

        group_objects_for_format.append(grp_obj)

        g_name = _stix_get(grp_obj, "name")
        g_stix_id = _stix_get(grp_obj, "id")
        g_aliases = _get_aliases(grp_obj)
        g_desc = _stix_get(grp_obj, "description") if include_description else None

        try:
            g_attack_id = attack_data.get_attack_id(g_stix_id) if g_stix_id else None
        except Exception:
            g_attack_id = None

        relationships_info = [_format_rel_edge(r, include_description=include_description) for r in rels]

        groups_structured.append(
            {
                "attack_id": g_attack_id,
                "name": g_name,
                "aliases": g_aliases,
                "stix_id": g_stix_id,
                "description": g_desc,
                "relationships": relationships_info,
            }
        )

    formatted = ""
    if include_formatted and group_objects_for_format:
        formatted = format_objects(
            group_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "found": True,
        "campaign": campaign_info,
        "count": len(groups_structured),
        "groups": groups_structured,
        "formatted": formatted,
        "message": (
            f"Found {len(groups_structured)} group(s) attributed to campaign "
            f"STIX ID '{campaign_stix_id}' in domain '{domain}'."
        ),
    }

#####################################################################
    # Software functions
#####################################################################
@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_software_by_alias(
    alias: str,
    domain: str = "enterprise",
    include_description: bool = True,
    remove_revoked_deprecated: bool = True,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Find software/malware by alias (e.g., 'Solorigate', 'SUNSHUTTLE', 'Darkmoon').

    Many malware/tools have multiple alternative names. This tool searches
    the software catalog for exact case-insensitive alias matches (trimming
    surrounding whitespace) against software names and `x_mitre_aliases`.

    Args:
        alias: Alias to search for (e.g., 'Solorigate', 'SUNSHUTTLE').
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include description fields.
        remove_revoked_deprecated: Whether to exclude revoked/deprecated software (default: True).
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
          "alias": "<alias>",
          "count": <number of matches>,
          "software": [
            {
              "attack_id": "<SXXXX or MXXXX or None>",
              "name": "<software name>",
              "aliases": [...],
              "stix_id": "<malware--UUID or tool--UUID>",
              "type": "<malware|tool|...>",
              "description": "<text or null>"
            },
            ...
          ],
          "formatted": "<human readable output>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)
    alias_norm = (alias or "").strip().lower()

    # Exact case-insensitive match against software name and aliases
    results: List[Any] = []
    if alias_norm:
        try:
            all_sw = attack_data.get_software(
                remove_revoked_deprecated=remove_revoked_deprecated
            ) or []
            results = [
                sw for sw in all_sw
                if alias_norm == (_stix_get(sw, "name", "") or "").strip().lower()
                or any(
                    alias_norm == (a or "").strip().lower()
                    for a in _get_aliases(sw)
                )
            ]
            results.sort(
                key=lambda sw: (
                    (_stix_get(sw, "name", "") or "").lower(),
                    str(_stix_get(sw, "id", "") or ""),
                )
            )
        except Exception:
            results = []

    if not results:
        return {
            "alias": alias,
            "count": 0,
            "software": [],
            "formatted": "",
            "message": (
                f"No software found for alias '{alias}' "
                f"in domain '{domain}'."
            ),
        }

    structured = []
    software_objects_for_format = []

    for sw in results:
        s_name = _stix_get(sw, "name")
        s_stix_id = _stix_get(sw, "id")
        s_aliases = _get_aliases(sw)
        s_type = _stix_get(sw, "type")
        s_desc = _stix_get(sw, "description") if include_description else None

        # External ATT&CK ID (e.g., SXXXX)
        try:
            s_attack_id = attack_data.get_attack_id(s_stix_id) if s_stix_id else None
        except Exception:
            s_attack_id = None

        software_objects_for_format.append(sw)

        structured.append(
            {
                "attack_id": s_attack_id,
                "name": s_name,
                "aliases": s_aliases,
                "stix_id": s_stix_id,
                "type": s_type,
                "description": s_desc,
            }
        )

    # Optional human-readable formatting
    formatted = ""
    if include_formatted and software_objects_for_format:
        formatted = format_objects(
            software_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "alias": alias,
        "count": len(structured),
        "software": structured,
        "formatted": formatted,
        "message": (
            f"Found {len(structured)} software item(s) matching alias "
            f"'{alias}' in domain '{domain}'."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_software_using_technique(
    technique_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
    limit: PageLimit = DEFAULT_PAGE_LIMIT,
    offset: PageOffset = 0,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Get all software (malware/tools) that use a specific technique, with pagination.

    This is a reverse lookup: Technique → Software, sorted deterministically by attack_id ascending.
    Accepts either a STIX ID ("attack-pattern--UUID") or an ATT&CK ID (e.g., "T1190").

    Args:
        technique_stix_id: STIX ID ("attack-pattern--UUID") or ATT&CK ID (e.g., "T1190").
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include software descriptions.
        limit: Maximum number of software items to return per page (1-200).
        offset: Zero-based starting index for pagination (>= 0).
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
          "found": bool,
          "technique": {
              "attack_id": "TXXXX or TXXXX.YYY" | null,
              "name": "<technique name or null>",
              "stix_id": "<attack-pattern--UUID>",
              "description": "<text or null>",
          } | null,

          "count": <number of software objects in this page>,
          "total_count": <total number of software objects>,
          "offset": <page offset>,
          "limit": <page limit>,
          "has_more": bool,
          "next_offset": int | null,

          "software": [
            {
              "attack_id": "SXXXX or similar" | null,
              "name": "<software name>",
              "aliases": [...],
              "stix_id": "<software STIX ID>",
              "type": "<malware|tool|...>",
              "description": "<text or null>",
              "relationships": [
                {
                  "stix_id": "<relationship--UUID>",
                  "relationship_type": "uses",
                  "description": "<relationship description or null>",
                  "source_ref": "<source STIX ID>",
                  "target_ref": "<target STIX ID>",
                },
                ...
              ]
            },
            ...
          ],

          "formatted": "<human-readable list of software>",
          "message": "<status summary>"
        }
    """
    safe_limit, safe_offset = _validate_pagination(limit, offset)
    attack_data = get_attack_data(domain)

    resolved_id, tech_obj, err = _resolve_stix_object(
        technique_stix_id, domain=domain, expected_stix_type="attack-pattern"
    )
    if resolved_id is None:
        return {
            "found": False,
            "technique": None,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "software": [],
            "formatted": "",
            "message": err or f"Technique '{technique_stix_id}' not found in domain '{domain}'.",
        }
    technique_stix_id = resolved_id

    technique_info: Optional[Dict[str, Any]] = None
    if tech_obj is not None:
        t_name = _stix_get(tech_obj, "name")
        t_desc = _stix_get(tech_obj, "description") if include_description else None
        try:
            t_attack_id = attack_data.get_attack_id(technique_stix_id)
        except Exception:
            t_attack_id = None

        technique_info = {
            "attack_id": t_attack_id,
            "name": t_name,
            "stix_id": technique_stix_id,
            "description": t_desc,
        }

    # Call MITRE helper: software that uses this technique
    try:
        rel_entries = attack_data.get_software_using_technique(technique_stix_id)
    except Exception:
        rel_entries = []

    if not rel_entries:
        return {
            "found": True,
            "technique": technique_info,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "software": [],
            "formatted": "",
            "message": (
                f"No software found using technique STIX ID "
                f"'{technique_stix_id}' in domain '{domain}'."
            ),
        }

    normalized_entries: List[Tuple[Tuple[int, str, str, str], Any, Optional[str], Optional[str], Optional[str], List[Any]]] = []

    for entry in rel_entries:
        if isinstance(entry, dict) and ("object" in entry or "relationships" in entry):
            sw_obj = entry.get("object", entry)
            rels = entry.get("relationships", [])
        else:
            sw_obj = entry
            rels = []

        if sw_obj is None:
            continue

        s_name = _stix_get(sw_obj, "name")
        s_stix_id = _stix_get(sw_obj, "id")
        try:
            s_attack_id = attack_data.get_attack_id(s_stix_id) if s_stix_id else None
        except Exception:
            s_attack_id = None

        normalized_entries.append(
            (_attack_id_sort_key(s_attack_id, s_name, s_stix_id), sw_obj, s_attack_id, s_name, s_stix_id, rels)
        )

    normalized_entries.sort(key=lambda item: item[0])
    page_entries, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        normalized_entries, limit=limit, offset=offset
    )

    software_structured: List[Dict[str, Any]] = []
    software_objects_for_format: List[Any] = []

    for _sort_key, sw_obj, s_attack_id, s_name, s_stix_id, rels in page_entries:
        software_objects_for_format.append(sw_obj)
        s_type = _stix_get(sw_obj, "type")
        s_aliases = _get_aliases(sw_obj)
        s_desc = _stix_get(sw_obj, "description") if include_description else None
        relationships_info = [_format_rel_edge(r, include_description=include_description) for r in rels]

        software_structured.append(
            {
                "attack_id": s_attack_id,
                "name": s_name,
                "aliases": s_aliases,
                "stix_id": s_stix_id,
                "type": s_type,
                "description": s_desc,
                "relationships": relationships_info,
            }
        )

    formatted = ""
    if include_formatted and software_objects_for_format:
        formatted = format_objects(
            software_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "found": True,
        "technique": technique_info,
        "count": len(software_structured),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": next_offset,
        "software": software_structured,
        "formatted": formatted,
        "message": (
            f"Found {total_count} software object(s) using "
            f"technique STIX ID '{technique_stix_id}' in domain '{domain}' "
            f"(returning {len(software_structured)} at offset {safe_offset})."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_techniques_used_by_software(
    software_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
    limit: PageLimit = DEFAULT_PAGE_LIMIT,
    offset: PageOffset = 0,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Get all techniques used by specific software/malware, with pagination.

    This shows what ATT&CK techniques a given software (tool/malware) is
    capable of performing, sorted deterministically by attack_id ascending.
    Accepts either a STIX ID or an ATT&CK ID (e.g., "S0154").

    Args:
        software_stix_id: STIX ID ("malware--UUID", "tool--UUID") or ATT&CK ID (e.g., "S0154").
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include technique descriptions.
        limit: Maximum number of techniques to return per page (1-200).
        offset: Zero-based starting index for pagination (>= 0).
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
          "found": bool,
          "software": {
              "attack_id": "SXXXX or similar" | null,
              "name": "<software name or null>",
              "stix_id": "<software STIX ID>",
              "type": "<malware|tool|...> or null",
              "description": "<text or null>",
          } | null,

          "count": <number of techniques in this page>,
          "total_count": <total number of techniques>,
          "offset": <page offset>,
          "limit": <page limit>,
          "has_more": bool,
          "next_offset": int | null,

          "techniques": [
            {
              "attack_id": "TXXXX or TXXXX.YYY" | null,
              "name": "<technique name>",
              "stix_id": "<attack-pattern--UUID>",
              "description": "<text or null>",
              "relationships": [
                {
                  "stix_id": "<relationship--UUID>",
                  "relationship_type": "uses",
                  "description": "<relationship description or null>",
                  "source_ref": "<source STIX ID>",
                  "target_ref": "<target STIX ID>",
                },
                ...
              ]
            },
            ...
          ],

          "formatted": "<human-readable list of techniques>",
          "message": "<status summary>"
        }
    """
    safe_limit, safe_offset = _validate_pagination(limit, offset)
    attack_data = get_attack_data(domain)

    resolved_id, sw_obj, err = _resolve_stix_object(
        software_stix_id, domain=domain, expected_stix_type=("malware", "tool")
    )
    if resolved_id is None:
        return {
            "found": False,
            "software": None,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "techniques": [],
            "formatted": "",
            "message": err or f"Software '{software_stix_id}' not found in domain '{domain}'.",
        }
    software_stix_id = resolved_id

    software_info: Optional[Dict[str, Any]] = None
    if sw_obj is not None:
        s_name = _stix_get(sw_obj, "name")
        s_type = _stix_get(sw_obj, "type")
        s_desc = _stix_get(sw_obj, "description") if include_description else None
        try:
            s_attack_id = attack_data.get_attack_id(software_stix_id)
        except Exception:
            s_attack_id = None

        software_info = {
            "attack_id": s_attack_id,
            "name": s_name,
            "stix_id": software_stix_id,
            "type": s_type,
            "description": s_desc,
        }

    # Call MITRE helper: techniques used by this software
    try:
        rel_entries = attack_data.get_techniques_used_by_software(software_stix_id)
    except Exception:
        rel_entries = []

    if not rel_entries:
        return {
            "found": True,
            "software": software_info,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "techniques": [],
            "formatted": "",
            "message": (
                f"No techniques found for software STIX ID "
                f"'{software_stix_id}' in domain '{domain}'."
            ),
        }

    normalized_entries: List[Tuple[Tuple[int, str, str, str], Any, Optional[str], Optional[str], Optional[str], List[Any]]] = []

    for entry in rel_entries:
        if isinstance(entry, dict) and ("object" in entry or "relationships" in entry):
            tech_obj = entry.get("object", entry)
            rels = entry.get("relationships", [])
        else:
            tech_obj = entry
            rels = []

        if tech_obj is None:
            continue

        t_name = _stix_get(tech_obj, "name")
        t_stix_id = _stix_get(tech_obj, "id")
        try:
            t_attack_id = attack_data.get_attack_id(t_stix_id) if t_stix_id else None
        except Exception:
            t_attack_id = None

        normalized_entries.append(
            (_attack_id_sort_key(t_attack_id, t_name, t_stix_id), tech_obj, t_attack_id, t_name, t_stix_id, rels)
        )

    normalized_entries.sort(key=lambda item: item[0])
    page_entries, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        normalized_entries, limit=limit, offset=offset
    )

    techniques_structured: List[Dict[str, Any]] = []
    technique_objects_for_format: List[Any] = []

    for _sort_key, tech_obj, t_attack_id, t_name, t_stix_id, rels in page_entries:
        technique_objects_for_format.append(tech_obj)
        t_desc = _stix_get(tech_obj, "description") if include_description else None
        relationships_info = [_format_rel_edge(r, include_description=include_description) for r in rels]

        techniques_structured.append(
            {
                "attack_id": t_attack_id,
                "name": t_name,
                "stix_id": t_stix_id,
                "description": t_desc,
                "relationships": relationships_info,
            }
        )

    formatted = ""
    if include_formatted and technique_objects_for_format:
        formatted = format_objects(
            technique_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "found": True,
        "software": software_info,
        "count": len(techniques_structured),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": next_offset,
        "techniques": techniques_structured,
        "formatted": formatted,
        "message": (
            f"Found {total_count} technique(s) used by software "
            f"STIX ID '{software_stix_id}' in domain '{domain}' "
            f"(returning {len(techniques_structured)} at offset {safe_offset})."
        ),
    }

#####################################################################
    # "Get All" functions for MITRE ATT&CK objects
#####################################################################

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_all_techniques(
    domain: str = "enterprise",
    remove_revoked_deprecated: bool = True,
    include_description: bool = False,
    limit: PageLimit = DEFAULT_PAGE_LIMIT,
    offset: PageOffset = 0,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Get all ATT&CK techniques for a given domain.

    Args:
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        remove_revoked_deprecated: Whether to exclude revoked/deprecated techniques.
        include_description: Whether to include technique descriptions.
        limit: Maximum number of items to return per page (1-200).
        offset: Zero-based starting index for pagination (>= 0).
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
          "domain": "<domain>",
          "count": <number of techniques in this page>,
          "total_count": <total number of techniques>,
          "offset": <offset>,
          "limit": <limit>,
          "has_more": <bool>,
          "next_offset": <int or null>,
          "techniques": [
            {
              "attack_id": "TXXXX or TXXXX.YYY",
              "name": "<technique name>",
              "stix_id": "<attack-pattern--UUID>",
              "description": "<text or null>",
              "tactics": [ "<tactic 1>", "<tactic 2>", ... ]
            },
            ...
          ],
          "formatted": "<optional human-readable output>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)
    safe_limit, safe_offset = _validate_pagination(limit, offset)

    try:
        techniques = attack_data.get_techniques(
            remove_revoked_deprecated=remove_revoked_deprecated
        )
    except Exception:
        return {
            "domain": domain,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "techniques": [],
            "formatted": "",
            "message": f"Unable to retrieve techniques for domain '{domain}'."
        }

    if not techniques:
        return {
            "domain": domain,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "techniques": [],
            "formatted": "",
            "message": f"No techniques found in domain '{domain}'."
        }

    techniques_sorted = sorted(
        techniques,
        key=lambda t: (
            str(_stix_get(t, "name") or ""),
            str(_stix_get(t, "id") or ""),
        ),
    )
    page_techniques, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        techniques_sorted, limit=limit, offset=offset
    )

    structured = []
    for tech in page_techniques:
        name = _stix_get(tech, "name")
        stix_id = _stix_get(tech, "id")
        description = _stix_get(tech, "description") if include_description else None
        try:
            attack_id = attack_data.get_attack_id(stix_id) if stix_id else None
        except Exception:
            attack_id = None
        tactics = _extract_tactic_names(tech)

        structured.append(
            {
                "attack_id": attack_id,
                "name": name,
                "stix_id": stix_id,
                "description": description,
                "tactics": tactics,
            }
        )

    formatted = ""
    if include_formatted and page_techniques:
        formatted = format_objects(
            page_techniques,
            include_description=include_description,
            domain=domain,
        )

    return {
        "domain": domain,
        "count": len(structured),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": next_offset,
        "techniques": structured,
        "formatted": formatted,
        "message": (
            f"Found {total_count} technique(s) in domain '{domain}' "
            f"(remove_revoked_deprecated={remove_revoked_deprecated}, returning {len(structured)} at offset {safe_offset})."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_all_subtechniques(
    domain: str = "enterprise",
    remove_revoked_deprecated: bool = True,
    include_description: bool = False,
    limit: PageLimit = DEFAULT_PAGE_LIMIT,
    offset: PageOffset = 0,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Get all subtechniques in a given ATT&CK domain.

    Subtechniques are more specific versions of parent techniques,
    e.g., T1566.001 and T1566.002 are subtechniques of T1566.

    Args:
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        remove_revoked_deprecated: Whether to exclude revoked/deprecated subtechniques.
        include_description: Whether to include descriptions.
        limit: Maximum number of items to return per page (1-200).
        offset: Zero-based starting index for pagination (>= 0).
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
          "domain": "<domain>",
          "count": <number of subtechniques in this page>,
          "total_count": <total number of subtechniques>,
          "offset": <offset>,
          "limit": <limit>,
          "has_more": <bool>,
          "next_offset": <int or null>,
          "subtechniques": [
            {
              "attack_id": "<TXXXX.YYY>",
              "name": "<subtechnique name>",
              "stix_id": "<attack-pattern--UUID>",
              "description": "<text or null>",
              "tactics": ["<Tactic 1>", "<Tactic 2>", ...],
              "parent_attack_id": "<TXXXX>",
              "parent_name": "<parent technique name>",
              "parent_stix_id": "<attack-pattern--UUID>"
            },
            ...
          ],
          "formatted": "<optional human-readable output>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)
    safe_limit, safe_offset = _validate_pagination(limit, offset)

    try:
        subtechniques = attack_data.get_subtechniques(
            remove_revoked_deprecated=remove_revoked_deprecated,
        ) or []
    except Exception:
        try:
            all_techniques = attack_data.get_techniques(
                remove_revoked_deprecated=remove_revoked_deprecated,
                include_subtechniques=True,
            ) or []
            subtechniques = [
                t for t in all_techniques if bool(_stix_get(t, "x_mitre_is_subtechnique", False))
            ]
        except Exception:
            return {
                "domain": domain,
                "count": 0,
                "total_count": 0,
                "offset": safe_offset,
                "limit": safe_limit,
                "has_more": False,
                "next_offset": None,
                "subtechniques": [],
                "formatted": "",
                "message": f"Unable to retrieve techniques for domain '{domain}'.",
            }

    if not subtechniques:
        return {
            "domain": domain,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "subtechniques": [],
            "formatted": "",
            "message": (
                f"No subtechniques found in domain '{domain}' "
                f"(remove_revoked_deprecated={remove_revoked_deprecated})."
            ),
        }

    subtechniques_sorted = sorted(
        subtechniques,
        key=lambda t: (
            str(_stix_get(t, "name") or ""),
            str(_stix_get(t, "id") or ""),
        ),
    )
    page_subs, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        subtechniques_sorted, limit=limit, offset=offset
    )

    structured: List[Dict[str, Any]] = []
    for t in page_subs:
        stix_id = _stix_get(t, "id")
        name = _stix_get(t, "name")
        description = _stix_get(t, "description") if include_description else None
        tactics = _extract_tactic_names(t)

        try:
            sub_attack_id = attack_data.get_attack_id(stix_id) if stix_id else None
        except Exception:
            sub_attack_id = None

        parent_stix_id = None
        parent_name = None
        parent_attack_id = None
        if stix_id:
            try:
                parent_raw = attack_data.get_parent_technique_of_subtechnique(stix_id)
                if isinstance(parent_raw, list):
                    parent_raw = parent_raw[0] if parent_raw else None
                parent_obj = _unwrap_stix_object(parent_raw)
                if parent_obj is not None:
                    parent_stix_id = _stix_get(parent_obj, "id")
                    parent_name = _stix_get(parent_obj, "name")
                    if parent_stix_id:
                        parent_attack_id = attack_data.get_attack_id(parent_stix_id)
            except Exception:
                pass

        structured.append(
            {
                "attack_id": sub_attack_id,
                "name": name,
                "stix_id": stix_id,
                "description": description,
                "tactics": tactics,
                "parent_attack_id": parent_attack_id,
                "parent_name": parent_name,
                "parent_stix_id": parent_stix_id,
            }
        )

    formatted = (
        format_objects(
            page_subs,
            include_description=include_description,
            domain=domain,
        )
        if include_formatted
        else ""
    )

    return {
        "domain": domain,
        "count": len(structured),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": next_offset,
        "subtechniques": structured,
        "formatted": formatted,
        "message": (
            f"Found {total_count} subtechnique(s) in domain '{domain}' "
            f"(remove_revoked_deprecated={remove_revoked_deprecated}, returning {len(structured)} at offset {safe_offset})."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_all_parent_techniques(
    domain: str = "enterprise",
    remove_revoked_deprecated: bool = True,
    include_description: bool = False,
    limit: PageLimit = DEFAULT_PAGE_LIMIT,
    offset: PageOffset = 0,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Get all parent techniques (exclude subtechniques) in a given domain.

    Parent techniques are the main techniques without a dot in their ATT&CK ID,
    e.g., T1566, T1055 (not T1566.001).

    Args:
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        remove_revoked_deprecated: Whether to exclude revoked/deprecated techniques.
        include_description: Whether to include descriptions.
        limit: Maximum number of items to return per page (1-200).
        offset: Zero-based starting index for pagination (>= 0).
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
          "domain": "<domain>",
          "count": <number of parent techniques in this page>,
          "total_count": <total number of parent techniques>,
          "offset": <offset>,
          "limit": <limit>,
          "has_more": <bool>,
          "next_offset": <int or null>,
          "parent_techniques": [
            {
              "attack_id": "<TXXXX>",
              "name": "<technique name>",
              "stix_id": "<attack-pattern--UUID>",
              "description": "<text or null>",
              "tactics": ["<Tactic 1>", "<Tactic 2>", ...]
            },
            ...
          ],
          "formatted": "<optional human-readable output>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)
    safe_limit, safe_offset = _validate_pagination(limit, offset)

    try:
        techniques = attack_data.get_techniques(
            remove_revoked_deprecated=remove_revoked_deprecated
        )
    except Exception:
        return {
            "domain": domain,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "parent_techniques": [],
            "formatted": "",
            "message": f"Unable to retrieve techniques for domain '{domain}'.",
        }

    parent_candidates: List[Tuple[str, Any]] = []
    for t in techniques:
        stix_id = _stix_get(t, "id")
        if not stix_id:
            continue
        try:
            attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            attack_id = None
        if not attack_id or "." in attack_id:
            continue
        parent_candidates.append((attack_id, t))

    if not parent_candidates:
        return {
            "domain": domain,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "parent_techniques": [],
            "formatted": "",
            "message": (
                f"No parent techniques found in domain '{domain}' "
                f"(remove_revoked_deprecated={remove_revoked_deprecated})."
            ),
        }

    parent_candidates.sort(
        key=lambda pair: (
            pair[0],
            str(_stix_get(pair[1], "id") or ""),
        )
    )
    page_pairs, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        parent_candidates, limit=limit, offset=offset
    )

    parent_objects: List[Any] = []
    structured: List[Dict[str, Any]] = []
    for attack_id, t in page_pairs:
        parent_objects.append(t)
        structured.append(
            {
                "attack_id": attack_id,
                "name": _stix_get(t, "name"),
                "stix_id": _stix_get(t, "id"),
                "description": _stix_get(t, "description") if include_description else None,
                "tactics": _extract_tactic_names(t),
            }
        )

    formatted = (
        format_objects(
            parent_objects,
            include_description=include_description,
            domain=domain,
        )
        if include_formatted
        else ""
    )

    return {
        "domain": domain,
        "count": len(structured),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": next_offset,
        "parent_techniques": structured,
        "formatted": formatted,
        "message": (
            f"Found {total_count} parent technique(s) in domain '{domain}' "
            f"(remove_revoked_deprecated={remove_revoked_deprecated}, returning {len(structured)} at offset {safe_offset})."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_all_groups(
    domain: str = "enterprise",
    remove_revoked_deprecated: bool = True,
    include_description: bool = False,
    limit: PageLimit = DEFAULT_PAGE_LIMIT,
    offset: PageOffset = 0,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Get all APT groups (intrusion sets) in a domain.

    Args:
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        remove_revoked_deprecated: Whether to exclude revoked/deprecated groups.
        include_description: Whether to include descriptions.
        limit: Maximum number of items to return per page (1-200).
        offset: Zero-based starting index for pagination (>= 0).
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
          "domain": "<domain>",
          "count": <number of groups in this page>,
          "total_count": <total number of groups>,
          "offset": <offset>,
          "limit": <limit>,
          "has_more": <bool>,
          "next_offset": <int or null>,
          "groups": [
            {
              "attack_id": "GXXXX",
              "name": "<group name>",
              "aliases": [...],
              "stix_id": "<intrusion-set--UUID>",
              "description": "<text or null>"
            },
            ...
          ],
          "formatted": "<optional human-readable listing>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)
    safe_limit, safe_offset = _validate_pagination(limit, offset)

    try:
        groups = attack_data.get_groups(
            remove_revoked_deprecated=remove_revoked_deprecated
        )
    except Exception:
        return {
            "domain": domain,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "groups": [],
            "formatted": "",
            "message": f"Unable to retrieve groups for domain '{domain}'."
        }

    if not groups:
        return {
            "domain": domain,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "groups": [],
            "formatted": "",
            "message": (
                f"No APT groups found in domain '{domain}' "
                f"(remove_revoked_deprecated={remove_revoked_deprecated})."
            )
        }

    groups_sorted = sorted(
        groups,
        key=lambda g: (
            str(_stix_get(g, "name") or ""),
            str(_stix_get(g, "id") or ""),
        ),
    )
    page_groups, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        groups_sorted, limit=limit, offset=offset
    )

    structured = []
    for g in page_groups:
        name = _stix_get(g, "name")
        stix_id = _stix_get(g, "id")
        aliases = _get_aliases(g)
        description = _stix_get(g, "description") if include_description else None
        try:
            attack_id = attack_data.get_attack_id(stix_id) if stix_id else None
        except Exception:
            attack_id = None

        structured.append(
            {
                "attack_id": attack_id,
                "name": name,
                "aliases": aliases,
                "stix_id": stix_id,
                "description": description,
            }
        )

    formatted = (
        format_objects(
            page_groups,
            include_description=include_description,
            domain=domain,
        )
        if include_formatted
        else ""
    )

    return {
        "domain": domain,
        "count": len(structured),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": next_offset,
        "groups": structured,
        "formatted": formatted,
        "message": (
            f"Found {total_count} APT group(s) in domain '{domain}' "
            f"(remove_revoked_deprecated={remove_revoked_deprecated}, returning {len(structured)} at offset {safe_offset})."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_all_software(
    domain: str = "enterprise",
    remove_revoked_deprecated: bool = True,
    include_description: bool = False,
    limit: PageLimit = DEFAULT_PAGE_LIMIT,
    offset: PageOffset = 0,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Get all software (malware and tools) in a domain.

    This is effectively an alias for the MITRE helper get_software(), but it
    returns structured results suitable for LLMs and clients.

    Args:
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        remove_revoked_deprecated: Whether to exclude revoked/deprecated software.
        include_description: Whether to include descriptions.
        limit: Maximum number of items to return per page (1-200).
        offset: Zero-based starting index for pagination (>= 0).
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
          "domain": "<domain>",
          "count": <number of software objects in this page>,
          "total_count": <total number of software objects>,
          "offset": <offset>,
          "limit": <limit>,
          "has_more": <bool>,
          "next_offset": <int or null>,
          "software": [
            {
              "attack_id": "<SXXXX or similar> | null",
              "name": "<software name>",
              "aliases": [...],
              "stix_id": "<malware--UUID or tool--UUID>",
              "type": "<malware|tool|...>",
              "description": "<text or null>"
            },
            ...
          ],
          "formatted": "<optional human-readable listing>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)
    safe_limit, safe_offset = _validate_pagination(limit, offset)

    try:
        software_items = attack_data.get_software(
            remove_revoked_deprecated=remove_revoked_deprecated
        )
    except Exception:
        return {
            "domain": domain,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "software": [],
            "formatted": "",
            "message": f"Unable to retrieve software for domain '{domain}'.",
        }

    if not software_items:
        return {
            "domain": domain,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "software": [],
            "formatted": "",
            "message": (
                f"No software found in domain '{domain}' "
                f"(remove_revoked_deprecated={remove_revoked_deprecated})."
            ),
        }

    software_sorted = sorted(
        software_items,
        key=lambda s: (
            str(_stix_get(s, "name") or ""),
            str(_stix_get(s, "id") or ""),
        ),
    )
    page_software, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        software_sorted, limit=limit, offset=offset
    )

    structured: List[Dict[str, Any]] = []
    for sw in page_software:
        name = _stix_get(sw, "name")
        stix_id = _stix_get(sw, "id")
        aliases = _get_aliases(sw)
        sw_type = _stix_get(sw, "type")
        description = _stix_get(sw, "description") if include_description else None
        try:
            attack_id = attack_data.get_attack_id(stix_id) if stix_id else None
        except Exception:
            attack_id = None

        structured.append(
            {
                "attack_id": attack_id,
                "name": name,
                "aliases": aliases,
                "stix_id": stix_id,
                "type": sw_type,
                "description": description,
            }
        )

    formatted = (
        format_objects(
            page_software,
            include_description=include_description,
            domain=domain,
        )
        if include_formatted
        else ""
    )

    return {
        "domain": domain,
        "count": len(structured),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": next_offset,
        "software": structured,
        "formatted": formatted,
        "message": (
            f"Found {total_count} software object(s) in domain '{domain}' "
            f"(remove_revoked_deprecated={remove_revoked_deprecated}, returning {len(structured)} at offset {safe_offset})."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_all_mitigations(
    domain: str = "enterprise",
    remove_revoked_deprecated: bool = True,
    include_description: bool = True,
    limit: PageLimit = DEFAULT_PAGE_LIMIT,
    offset: PageOffset = 0,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Get all mitigations (defensive countermeasures) in a domain.

    Mitigations are security controls or practices that can reduce the
    effectiveness of adversary techniques (e.g., M1013, M1017).

    Args:
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        remove_revoked_deprecated: Whether to exclude revoked/deprecated mitigations.
        include_description: Whether to include descriptions.
        limit: Maximum number of items to return per page (1-200).
        offset: Zero-based starting index for pagination (>= 0).
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
          "domain": "<domain>",
          "count": <number of mitigations in this page>,
          "total_count": <total number of mitigations>,
          "offset": <offset>,
          "limit": <limit>,
          "has_more": <bool>,
          "next_offset": <int or null>,
          "mitigations": [
            {
              "attack_id": "MXXXX" | null,
              "name": "<mitigation name>",
              "stix_id": "<course-of-action--UUID>",
              "description": "<text or null>"
            },
            ...
          ],
          "formatted": "<optional human-readable output>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)
    safe_limit, safe_offset = _validate_pagination(limit, offset)

    try:
        mitigations = attack_data.get_mitigations(
            remove_revoked_deprecated=remove_revoked_deprecated
        )
    except Exception:
        return {
            "domain": domain,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "mitigations": [],
            "formatted": "",
            "message": f"Unable to retrieve mitigations for domain '{domain}'.",
        }

    if not mitigations:
        return {
            "domain": domain,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "mitigations": [],
            "formatted": "",
            "message": (
                f"No mitigations found in domain '{domain}' "
                f"(remove_revoked_deprecated={remove_revoked_deprecated})."
            ),
        }

    mitigations_sorted = sorted(
        mitigations,
        key=lambda m: (
            str(_stix_get(m, "name") or ""),
            str(_stix_get(m, "id") or ""),
        ),
    )
    page_mitigations, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        mitigations_sorted, limit=limit, offset=offset
    )

    structured: List[Dict[str, Any]] = []
    for m in page_mitigations:
        name = _stix_get(m, "name")
        stix_id = _stix_get(m, "id")
        description = _stix_get(m, "description") if include_description else None
        try:
            attack_id = attack_data.get_attack_id(stix_id) if stix_id else None
        except Exception:
            attack_id = None

        structured.append(
            {
                "attack_id": attack_id,
                "name": name,
                "stix_id": stix_id,
                "description": description,
            }
        )

    formatted = (
        format_objects(
            page_mitigations,
            include_description=include_description,
            domain=domain,
        )
        if include_formatted
        else ""
    )

    return {
        "domain": domain,
        "count": len(structured),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": next_offset,
        "mitigations": structured,
        "formatted": formatted,
        "message": (
            f"Found {total_count} mitigation(s) in domain '{domain}' "
            f"(remove_revoked_deprecated={remove_revoked_deprecated}, returning {len(structured)} at offset {safe_offset})."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_all_tactics(
    domain: str = "enterprise",
    include_description: bool = True,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Get all ATT&CK tactics for a domain.

    Tactics represent the adversary's tactical goals (e.g., Initial Access,
    Stealth, Defense Impairment, Persistence).

    Args:
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics')
        include_description: Whether to include tactic descriptions.
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
          "domain": "<domain>",
          "count": <number>,
          "tactics": [
             {
               "attack_id": "<TAxxxx>" | null,
               "name": "...",
               "stix_id": "x-mitre-tactic--UUID",
               "description": "...",
             }
          ],
          "formatted": "<optional human-readable text>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # Retrieve tactic objects
    try:
        tactics = attack_data.get_tactics(remove_revoked_deprecated=True)
    except Exception:
        return {
            "domain": domain,
            "count": 0,
            "tactics": [],
            "formatted": "",
            "message": f"Unable to retrieve tactics for domain '{domain}'.",
        }

    if not tactics:
        return {
            "domain": domain,
            "count": 0,
            "tactics": [],
            "formatted": "",
            "message": f"No tactics found in domain '{domain}'.",
        }

    structured = []
    tactics_for_format = []

    for t in tactics:
        tactics_for_format.append(t)

        name = getattr(t, "name", None)
        stix_id = getattr(t, "id", None)
        description = getattr(t, "description", None) if include_description else None

        # ATT&CK external ID (TAxxxx)
        try:
            attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            attack_id = None

        structured.append(
            {
                "attack_id": attack_id,
                "name": name,
                "stix_id": stix_id,
                "description": description,
            }
        )

    # Human readable formatting (optional)
    formatted = (
        format_objects(
            tactics_for_format,
            include_description=include_description,
            domain=domain,
        )
        if include_formatted
        else ""
    )

    return {
        "domain": domain,
        "count": len(structured),
        "tactics": structured,
        "formatted": formatted,
        "message": f"Found {len(structured)} tactic(s) in domain '{domain}'.",
    }


@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_all_matrices(
    domain: str = "enterprise",
    remove_revoked_deprecated: bool = True,
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all ATT&CK matrices in a domain.

    Matrices are the top-level organizational structures in ATT&CK.
    Each domain typically has one or more matrices
    (e.g., Enterprise ATT&CK matrix).

    Args:
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        remove_revoked_deprecated: Whether to exclude revoked/deprecated matrices.
        include_description: Whether to include descriptions.

    Returns:
        {
          "domain": "<domain>",
          "count": <number of matrices>,
          "matrices": [
            {
              "attack_id": "<matrix ID or None>",
              "name": "<matrix name>",
              "stix_id": "<x-mitre-matrix--UUID>",
              "description": "<text or null>"
            },
            ...
          ],
          "formatted": "<optional human-readable output>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # Fetch matrices from MITRE library
    try:
        matrices = attack_data.get_matrices(
            remove_revoked_deprecated=remove_revoked_deprecated
        )
    except Exception:
        return {
            "domain": domain,
            "count": 0,
            "matrices": [],
            "formatted": "",
            "message": f"Unable to retrieve matrices for domain '{domain}'.",
        }

    if not matrices:
        return {
            "domain": domain,
            "count": 0,
            "matrices": [],
            "formatted": "",
            "message": (
                f"No matrices found in domain '{domain}' "
                f"(remove_revoked_deprecated={remove_revoked_deprecated})."
            ),
        }

    structured: List[Dict[str, Any]] = []
    matrices_for_format: List[Any] = []

    for m in matrices:
        matrices_for_format.append(m)

        if isinstance(m, dict):
            name = m.get("name")
            stix_id = m.get("id")
            description = m.get("description") if include_description else None
        else:
            name = getattr(m, "name", None)
            stix_id = getattr(m, "id", None)
            description = getattr(m, "description", None) if include_description else None

        # External ID if available (sometimes matrix IDs exist, sometimes not)
        try:
            attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            attack_id = None

        structured.append(
            {
                "attack_id": attack_id,
                "name": name,
                "stix_id": stix_id,
                "description": description,
            }
        )

    # Optional human-readable formatting
    formatted = format_objects(
        matrices_for_format,
        include_description=include_description,
        domain=domain,
    )

    return {
        "domain": domain,
        "count": len(structured),
        "matrices": structured,
        "formatted": formatted,
        "message": (
            f"Found {len(structured)} matrix/matrices in domain '{domain}' "
            f"(remove_revoked_deprecated={remove_revoked_deprecated})."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_all_campaigns(
    domain: str = "enterprise",
    remove_revoked_deprecated: bool = True,
    include_description: bool = True,
    limit: PageLimit = DEFAULT_PAGE_LIMIT,
    offset: PageOffset = 0,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Get all ATT&CK campaigns in a domain.

    Campaigns represent specific intrusion events or long-running operations
    attributed to threat actors (e.g., SolarWinds, Operation Ghost).

    Args:
        domain: ATT&CK domain ("enterprise", "mobile", "ics")
        remove_revoked_deprecated: Whether to exclude revoked/deprecated entries
        include_description: Include campaign descriptions in the output
        limit: Maximum number of items to return per page (1-200).
        offset: Zero-based starting index for pagination (>= 0).
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
          "domain": "<domain>",
          "count": <int>,
          "total_count": <int>,
          "offset": <int>,
          "limit": <int>,
          "has_more": <bool>,
          "next_offset": <int or null>,
          "campaigns": [
             {
                "attack_id": "<Cxxxx or None>",
                "name": "<campaign name>",
                "aliases": [...],
                "stix_id": "campaign--UUID",
                "description": "<text or null>"
             },
             ...
          ],
          "formatted": "<nicely formatted output>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)
    safe_limit, safe_offset = _validate_pagination(limit, offset)

    try:
        campaigns = attack_data.get_campaigns(
            remove_revoked_deprecated=remove_revoked_deprecated
        )
    except Exception:
        return {
            "domain": domain,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "campaigns": [],
            "formatted": "",
            "message": f"Unable to retrieve campaigns for domain '{domain}'.",
        }

    if not campaigns:
        return {
            "domain": domain,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "campaigns": [],
            "formatted": "",
            "message": (
                f"No campaigns found in domain '{domain}' "
                f"(remove_revoked_deprecated={remove_revoked_deprecated})."
            ),
        }

    campaigns_sorted = sorted(
        campaigns,
        key=lambda c: (
            str(_stix_get(c, "name") or ""),
            str(_stix_get(c, "id") or ""),
        ),
    )
    page_campaigns, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        campaigns_sorted, limit=limit, offset=offset
    )

    structured: List[Dict[str, Any]] = []
    for c in page_campaigns:
        name = _stix_get(c, "name")
        stix_id = _stix_get(c, "id")
        aliases = _get_aliases(c)
        description = _stix_get(c, "description") if include_description else None
        try:
            attack_id = attack_data.get_attack_id(stix_id) if stix_id else None
        except Exception:
            attack_id = None

        structured.append(
            {
                "attack_id": attack_id,
                "name": name,
                "aliases": aliases,
                "stix_id": stix_id,
                "description": description,
            }
        )

    formatted = (
        format_objects(
            page_campaigns,
            include_description=include_description,
            domain=domain,
        )
        if include_formatted
        else ""
    )

    return {
        "domain": domain,
        "count": len(structured),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": next_offset,
        "campaigns": structured,
        "formatted": formatted,
        "message": (
            f"Found {total_count} campaign(s) in domain '{domain}' "
            f"(remove_revoked_deprecated={remove_revoked_deprecated}, returning {len(structured)} at offset {safe_offset})."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_all_datasources(
    domain: str = "enterprise",
    remove_revoked_deprecated: bool = True,
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all ATT&CK data sources in a domain.

    Data sources represent *what* kind of telemetry you collect
    (e.g., Process Monitoring, Network Traffic, File Monitoring).

    Args:
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        remove_revoked_deprecated: Whether to exclude revoked/deprecated data sources.
        include_description: Whether to include descriptions.

    Returns:
        {
          "domain": "<domain>",
          "count": <number of data sources>,
          "datasources": [
            {
              "name": "<data source name>",
              "stix_id": "<x-mitre-data-source--UUID>",
              "description": "<text or null>",
              "platforms": ["<Windows>", "<Linux>", ...]  # if available
            },
            ...
          ],
          "formatted": "<optional human-readable output>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # Fetch data sources from MITRE library
    try:
        datasources = attack_data.get_datasources(
            remove_revoked_deprecated=remove_revoked_deprecated
        )
    except Exception:
        return {
            "domain": domain,
            "count": 0,
            "datasources": [],
            "formatted": "",
            "message": f"Unable to retrieve data sources for domain '{domain}'.",
        }

    if not datasources:
        msg = (
            f"No data sources found in domain '{domain}' "
            f"(remove_revoked_deprecated={remove_revoked_deprecated})."
        )
        if remove_revoked_deprecated:
            msg += (
                " Note: In ATT&CK v20.1, x-mitre-data-source objects are deprecated in favor of "
                "Detection Strategies and Analytics. Use get_detection_strategies_for_technique, "
                "get_analytics, or get_all_datacomponents instead, or pass "
                "remove_revoked_deprecated=False to inspect legacy data sources."
            )
        return {
            "domain": domain,
            "count": 0,
            "datasources": [],
            "formatted": "",
            "message": msg,
        }

    structured: List[Dict[str, Any]] = []
    ds_for_format: List[Any] = []

    for ds in datasources:
        ds_for_format.append(ds)

        if isinstance(ds, dict):
            name = ds.get("name")
            stix_id = ds.get("id")
            description = ds.get("description") if include_description else None
            platforms = ds.get("x_mitre_platforms") or ds.get("x-mitre-platforms") or []
        else:
            name = getattr(ds, "name", None)
            stix_id = getattr(ds, "id", None)
            description = getattr(ds, "description", None) if include_description else None
            platforms = getattr(ds, "x_mitre_platforms", []) or []

        structured.append(
            {
                "name": name,
                "stix_id": stix_id,
                "description": description,
                "platforms": platforms,
            }
        )

    # Optional human-readable formatting
    formatted = format_objects(
        ds_for_format,
        include_description=include_description,
        domain=domain,
    )

    return {
        "domain": domain,
        "count": len(structured),
        "datasources": structured,
        "formatted": formatted,
        "message": (
            f"Found {len(structured)} data source(s) in domain '{domain}' "
            f"(remove_revoked_deprecated={remove_revoked_deprecated})."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_all_datacomponents(
    domain: str = "enterprise",
    remove_revoked_deprecated: bool = True,
    include_description: bool = True,
    limit: PageLimit = DEFAULT_PAGE_LIMIT,
    offset: PageOffset = 0,
    include_formatted: bool = True,
    query: Annotated[
        str,
        Field(
            default="",
            description=(
                "Optional case-insensitive filter matched against attack_id (DCxxxx), "
                "name, description, and ATT&CK v20.1 log_sources (name / channel)."
            ),
        ),
    ] = "",
    include_log_sources: Annotated[
        bool,
        Field(
            default=True,
            description=(
                "Whether to embed the full `log_sources` array on each returned data component. "
                "Set False to return an empty `log_sources` list while keeping `log_source_count` "
                "to save tokens when browsing many data components."
            ),
        ),
    ] = True,
    log_source_filter: Annotated[
        str,
        Field(
            default="",
            description=(
                "Optional case-insensitive substring filter applied to each returned data "
                "component's `log_sources` (`name` / `channel`) when `include_log_sources=True` "
                "(e.g., 'linux', 'networkdevice', 'WinEventLog')."
            ),
        ),
    ] = "",
) -> Dict[str, Any]:
    """
    Get all ATT&CK data components in a domain.

    Data components are specific telemetry aspects that can be monitored
    (e.g., "Process Creation", "File Modification", "Network Connection Creation").
    In ATT&CK v20.1, each data component exposes `log_sources` (`x_mitre_log_sources`,
    listing concrete log source names and channels such as `auditd` or `Sysmon`) along
    with `log_source_count`, while legacy `data_source_*` fields are preserved for
    backward compatibility.

    Args:
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        remove_revoked_deprecated: Whether to exclude revoked/deprecated entries.
        include_description: Whether to include descriptions.
        limit: Maximum number of items to return per page (1-200).
        offset: Zero-based starting index for pagination (>= 0).
        include_formatted: If False, omits the human-readable formatted block to save tokens.
        query: Optional case-insensitive filter across attack_id (DCxxxx), name,
               description, and log_sources (name / channel).
        include_log_sources: If False, returns `log_sources: []` while keeping
                             `log_source_count` so callers can browse cheaply.
        log_source_filter: Optional case-insensitive substring filter applied to each
                           returned data component's `log_sources` (`name`/`channel`)
                           when `include_log_sources=True`.

    Returns:
        {
          "domain": "<domain>",
          "count": <number of data components in this page>,
          "total_count": <total number of data components>,
          "offset": <offset>,
          "limit": <limit>,
          "has_more": <bool>,
          "next_offset": <int or null>,
          "datacomponents": [
            {
              "attack_id": "<DCxxxx or null>",
              "name": "<data component name>",
              "stix_id": "<x-mitre-data-component--UUID>",
              "description": "<text or null>",
              "log_source_count": <int>,
              "log_sources": [{"name": "<log source>", "channel": "<channel>"}, ...],
              "data_source_stix_id": "<x-mitre-data-source--UUID or null>",
              "data_source_name": "<parent data source name or null>",
              "data_source_attack_id": "<data source ATT&CK ID or null>"
            },
            ...
          ],
          "formatted": "<optional human-readable output>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)
    safe_limit, safe_offset = _validate_pagination(limit, offset)
    raw_query = (query or "").strip()
    query_lower = raw_query.lower()
    raw_ls_filter = (log_source_filter or "").strip()
    ls_filter_lower = raw_ls_filter.lower()

    try:
        datacomponents = attack_data.get_datacomponents(
            remove_revoked_deprecated=remove_revoked_deprecated
        )
    except Exception:
        return {
            "domain": domain,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "datacomponents": [],
            "formatted": "",
            "message": f"Unable to retrieve data components for domain '{domain}'.",
        }

    if not datacomponents:
        return {
            "domain": domain,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "datacomponents": [],
            "formatted": "",
            "message": (
                f"No data components found in domain '{domain}' "
                f"(remove_revoked_deprecated={remove_revoked_deprecated})."
            ),
        }

    dc_with_ids: List[Tuple[str, Any, List[Dict[str, str]]]] = []
    for dc in datacomponents:
        sid = _stix_get(dc, "id")
        try:
            aid = attack_data.get_attack_id(sid) if sid else None
        except Exception:
            aid = None
        aid_str = aid or ""
        log_sources = _extract_dc_log_sources(dc)

        if query_lower:
            dc_name = str(_stix_get(dc, "name") or "").lower()
            dc_desc = str(_stix_get(dc, "description") or "").lower()
            ls_match = any(
                query_lower in ls.get("name", "").lower()
                or query_lower in ls.get("channel", "").lower()
                for ls in log_sources
            )
            if not (
                query_lower in aid_str.lower()
                or query_lower in dc_name
                or query_lower in dc_desc
                or ls_match
            ):
                continue

        dc_with_ids.append((aid_str, dc, log_sources))

    if not dc_with_ids:
        return {
            "domain": domain,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "datacomponents": [],
            "formatted": "",
            "message": (
                f"No data components in domain '{domain}' matched query '{raw_query}' "
                f"(remove_revoked_deprecated={remove_revoked_deprecated})."
            ),
        }

    dc_with_ids.sort(
        key=lambda item: (
            item[0] or "ZZZ",
            str(_stix_get(item[1], "name") or ""),
            str(_stix_get(item[1], "id") or ""),
        )
    )
    page_items, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        dc_with_ids, limit=limit, offset=offset
    )

    structured: List[Dict[str, Any]] = []
    dc_for_format: List[Any] = []

    for dc_aid_key, dc, log_sources in page_items:
        dc_for_format.append(dc)
        name = _stix_get(dc, "name")
        stix_id = _stix_get(dc, "id")
        description = _stix_get(dc, "description") if include_description else None
        ds_ref = _stix_get(dc, "x_mitre_data_source_ref") or _stix_get(dc, "x-mitre-data-source-ref")

        data_source_name = None
        data_source_attack_id = None
        data_source_stix_id = ds_ref

        if ds_ref:
            try:
                ds_obj = attack_data.get_object_by_stix_id(ds_ref)
            except Exception:
                ds_obj = None

            if ds_obj is not None:
                data_source_name = _stix_get(ds_obj, "name")
                ds_id_for_attack = _stix_get(ds_obj, "id")
                try:
                    data_source_attack_id = attack_data.get_attack_id(ds_id_for_attack) if ds_id_for_attack else None
                except Exception:
                    data_source_attack_id = None

        if not include_log_sources:
            out_log_sources: List[Dict[str, str]] = []
        elif ls_filter_lower:
            out_log_sources = [
                ls
                for ls in log_sources
                if ls_filter_lower in ls.get("name", "").lower()
                or ls_filter_lower in ls.get("channel", "").lower()
            ]
        else:
            out_log_sources = log_sources

        structured.append(
            {
                "attack_id": dc_aid_key or None,
                "name": name,
                "stix_id": stix_id,
                "description": description,
                "log_source_count": len(log_sources),
                "log_sources": out_log_sources,
                "data_source_stix_id": data_source_stix_id,
                "data_source_name": data_source_name,
                "data_source_attack_id": data_source_attack_id,
            }
        )

    formatted = (
        format_objects(
            dc_for_format,
            include_description=include_description,
            domain=domain,
        )
        if include_formatted
        else ""
    )

    query_clause = f" matching query '{raw_query}'" if query_lower else ""
    ls_clause = (
        f", log_source_filter='{raw_ls_filter}'"
        if (include_log_sources and ls_filter_lower)
        else (", include_log_sources=False" if not include_log_sources else "")
    )
    return {
        "domain": domain,
        "count": len(structured),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": next_offset,
        "datacomponents": structured,
        "formatted": formatted,
        "message": (
            f"Found {total_count} data component(s) in domain '{domain}'{query_clause} "
            f"(remove_revoked_deprecated={remove_revoked_deprecated}{ls_clause}, "
            f"returning {len(structured)} at offset {safe_offset})."
        ),
    }


# ---------------------------------------------------------------------------
# Technique → ICS Assets targeted (ICS domain only)
# ---------------------------------------------------------------------------

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_all_assets(
    domain: str = "ics",
    remove_revoked_deprecated: bool = True,
    include_description: bool = True,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Get all ATT&CK assets in a domain (primarily ICS).

    Assets represent industrial control system components 
    (PLC, HMI, Engineering Workstation, Control Server, etc.)

    Args:
        domain: ATT&CK domain ("ics" recommended)
        remove_revoked_deprecated: Exclude revoked/deprecated entries
        include_description: Include asset descriptions
        include_formatted: Include human-readable formatted text block (set False to save tokens)

    Returns:
        {
          "domain": "<domain>",
          "count": <number>,
          "assets": [
            {
              "name": "...",
              "stix_id": "x-mitre-asset--UUID",
              "description": "...",
              "attack_id": "<Axxxx or None>"
            }
          ],
          "formatted": "<human-readable output or empty string when include_formatted=False>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # Retrieve assets
    try:
        assets = attack_data.get_assets(
            remove_revoked_deprecated=remove_revoked_deprecated
        )
    except Exception:
        return {
            "domain": domain,
            "count": 0,
            "assets": [],
            "formatted": "",
            "message": f"Unable to retrieve assets for domain '{domain}'.",
        }

    if not assets:
        return {
            "domain": domain,
            "count": 0,
            "assets": [],
            "formatted": "",
            "message": (
                f"No assets found in domain '{domain}' "
                f"(remove_revoked_deprecated={remove_revoked_deprecated})."
            ),
        }

    structured: List[Dict[str, Any]] = []
    assets_for_format: List[Any] = []

    for asset in assets:
        assets_for_format.append(asset)

        # Extract metadata
        if isinstance(asset, dict):
            name = asset.get("name")
            stix_id = asset.get("id")
            description = asset.get("description") if include_description else None
        else:
            name = getattr(asset, "name", None)
            stix_id = getattr(asset, "id", None)
            description = getattr(asset, "description", None) if include_description else None

        # ATT&CK ID lookup (ICS assets sometimes have Ax000 identifiers)
        try:
            attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            attack_id = None

        structured.append(
            {
                "name": name,
                "stix_id": stix_id,
                "description": description,
                "attack_id": attack_id,
            }
        )

    # Human-readable formatting (not required for apps, useful for ChatGPT)
    formatted = (
        format_objects(
            assets_for_format,
            include_description=include_description,
            domain=domain,
        )
        if include_formatted
        else ""
    )

    return {
        "domain": domain,
        "count": len(structured),
        "assets": structured,
        "formatted": formatted,
        "message": (
            f"Found {len(structured)} asset(s) in domain '{domain}' "
            f"(remove_revoked_deprecated={remove_revoked_deprecated})."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_assets_targeted_by_technique(
    technique_stix_id: str,
    domain: str = "ics",
    include_description: bool = True,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Get all ICS assets targeted by a specific technique.

    Assets represent industrial control system components such as
    PLCs, RTUs, Engineering Workstations, HMIs, Control Servers, etc.
    Accepts either a STIX ID or an ATT&CK ID (e.g., "T0816").

    Args:
        technique_stix_id: Technique STIX UUID or ATT&CK ID (e.g., "T0816").
        domain: ATT&CK domain ('ics' strongly recommended).
        include_description: Include asset descriptions, if available.
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
          "found": bool,
          "technique": {
              "attack_id": "Txxxx",
              "name": "...",
              "stix_id": "<attack-pattern--UUID>"
          } | null,
          "count": int,
          "assets": [
            {
              "attack_id": "Axxxx",
              "name": "...",
              "stix_id": "<x-mitre-asset--UUID>",
              "description": "<optional text>",
              "asset_type": "<ICS component type>",
            },
            ...
          ],
          "formatted": "<multi-line readable text>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)

    resolved_id, tech_obj, err = _resolve_stix_object(
        technique_stix_id, domain=domain, expected_stix_type="attack-pattern"
    )
    if resolved_id is None:
        return {
            "found": False,
            "technique": None,
            "count": 0,
            "assets": [],
            "formatted": "",
            "message": err or f"Technique '{technique_stix_id}' not found in domain '{domain}'.",
        }
    technique_stix_id = resolved_id

    t_name = _stix_get(tech_obj, "name") if tech_obj is not None else None
    try:
        t_attack_id = attack_data.get_attack_id(technique_stix_id)
    except Exception:
        t_attack_id = None

    technique_info = {
        "attack_id": t_attack_id,
        "name": t_name,
        "stix_id": technique_stix_id,
    }

    try:
        assets = attack_data.get_assets_targeted_by_technique(
            technique_stix_id
        ) or []
    except Exception:
        assets = []

    if not assets:
        return {
            "found": True,
            "technique": technique_info,
            "count": 0,
            "assets": [],
            "formatted": "",
            "message": (
                f"No ICS assets found that are targeted by technique '{t_attack_id}' "
                f"in domain '{domain}'."
            ),
        }

    asset_entries = []
    unwrapped_assets = []
    for item in assets:
        a = _unwrap_stix_object(item)
        if a is None:
            continue
        unwrapped_assets.append(a)
        name = _stix_get(a, "name")
        stix_id = _stix_get(a, "id")
        desc = _stix_get(a, "description") if include_description else None
        asset_type = _stix_get(a, "x_mitre_asset_type")
        try:
            a_attack_id = attack_data.get_attack_id(stix_id) if stix_id else None
        except Exception:
            a_attack_id = None

        asset_entries.append(
            {
                "attack_id": a_attack_id,
                "name": name,
                "stix_id": stix_id,
                "description": desc,
                "asset_type": asset_type,
            }
        )

    formatted = (
        format_objects(
            unwrapped_assets,
            include_description=include_description,
            domain=domain,
        )
        if include_formatted
        else ""
    )

    return {
        "found": True,
        "technique": technique_info,
        "count": len(asset_entries),
        "assets": asset_entries,
        "formatted": formatted,
        "message": (
            f"Found {len(asset_entries)} ICS asset(s) targeted by technique "
            f"'{t_attack_id}' ({t_name}) in domain '{domain}'."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_techniques_targeting_asset(
    asset_stix_id: str,
    domain: str = "ics",
    include_description: bool = True,
    limit: PageLimit = DEFAULT_PAGE_LIMIT,
    offset: PageOffset = 0,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Get all techniques that target a specific ICS asset.

    Shows which adversary techniques can affect a given industrial
    control system component. Accepts either a STIX ID or an ATT&CK ID (e.g., "A0003").

    Args:
        asset_stix_id: STIX ID ("x-mitre-asset--UUID") or ATT&CK ID (e.g., "A0003") of the ICS asset.
        domain: Domain (default: 'ics').
        include_description: Whether to include descriptions in formatted output.
        limit: Maximum number of items to return per page (1-200).
        offset: Zero-based starting index for pagination (>= 0).
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
            "found": bool,
            "count": int,
            "total_count": int,
            "offset": int,
            "limit": int,
            "has_more": bool,
            "next_offset": int | null,
            "techniques": [
                {
                    "attack_id": "<ATT&CK ID>",
                    "id": "<ATT&CK ID>",
                    "name": "...",
                    "stix_id": "...",
                    "description": "..." | None
                },
                ...
            ],
            "formatted": "<optional pretty text>",
            "message": "..."
        }
    """
    attack_data = get_attack_data(domain)
    safe_limit, safe_offset = _validate_pagination(limit, offset)

    resolved_id, _asset_obj, err = _resolve_stix_object(
        asset_stix_id, domain=domain, expected_stix_type="x-mitre-asset"
    )
    if resolved_id is None:
        return {
            "found": False,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "techniques": [],
            "formatted": "",
            "message": err or f"Asset '{asset_stix_id}' not found in domain '{domain}'.",
        }
    asset_stix_id = resolved_id

    try:
        techniques = attack_data.get_techniques_targeting_asset(asset_stix_id) or []
    except Exception as e:
        return {
            "found": False,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "techniques": [],
            "formatted": "",
            "message": f"Error retrieving techniques: {e}",
        }

    if not techniques:
        return {
            "found": False,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "techniques": [],
            "formatted": "",
            "message": f"No techniques found targeting asset '{asset_stix_id}' in domain '{domain}'.",
        }

    unwrapped_all = [
        t for t in (_unwrap_stix_object(item) for item in techniques) if t is not None
    ]
    unwrapped_sorted = sorted(
        unwrapped_all,
        key=lambda t: (
            str(_stix_get(t, "name") or ""),
            str(_stix_get(t, "id") or ""),
        ),
    )
    page_techniques, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        unwrapped_sorted, limit=limit, offset=offset
    )

    out = []
    for tech in page_techniques:
        stix_id = _stix_get(tech, "id")
        try:
            attack_id = attack_data.get_attack_id(stix_id) if stix_id else None
        except Exception:
            attack_id = None
        out.append(
            {
                "attack_id": attack_id,
                "id": attack_id,
                "name": _stix_get(tech, "name"),
                "stix_id": stix_id,
                "description": _stix_get(tech, "description") if include_description else None,
            }
        )

    formatted = (
        format_objects(page_techniques, include_description=include_description, domain=domain)
        if include_formatted
        else ""
    )

    return {
        "found": True,
        "count": len(out),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": next_offset,
        "techniques": out,
        "formatted": formatted,
        "message": (
            f"Found {total_count} techniques targeting asset '{asset_stix_id}' "
            f"(returning {len(out)} at offset {safe_offset})."
        ),
    }

 #####################################################################
    # Campaign functions
#####################################################################

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_campaigns_using_technique(
    technique_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
    limit: PageLimit = DEFAULT_PAGE_LIMIT,
    offset: PageOffset = 0,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Get all campaigns that use a specific technique, with pagination.

    This is a reverse lookup: Technique → Campaigns, sorted deterministically by attack_id ascending.
    Accepts either a STIX ID ("attack-pattern--UUID") or an ATT&CK ID (e.g., "T1190").

    Args:
        technique_stix_id: Technique STIX UUID ("attack-pattern--UUID") or ATT&CK ID (e.g., "T1190").
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Whether to include campaign descriptions.
        limit: Maximum number of campaigns to return per page (1-200).
        offset: Zero-based starting index for pagination (>= 0).
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
          "found": bool,
          "technique": {
              "attack_id": "TXXXX or TXXXX.YYY" | null,
              "name": "<technique name or null>",
              "stix_id": "<attack-pattern--UUID>",
              "description": "<text or null>",
          } | null,

          "count": <number of campaigns in this page>,
          "total_count": <total number of campaigns>,
          "offset": <page offset>,
          "limit": <page limit>,
          "has_more": bool,
          "next_offset": int | null,

          "campaigns": [
            {
              "attack_id": "CXXXX" | null,
              "name": "<campaign name>",
              "aliases": [...],
              "stix_id": "<campaign--UUID>",
              "description": "<text or null>",
              "relationships": [
                {
                  "stix_id": "<relationship--UUID>",
                  "relationship_type": "<type>",
                  "description": "<relationship description or null>",
                  "source_ref": "<source STIX ID>",
                  "target_ref": "<target STIX ID>",
                },
                ...
              ]
            },
            ...
          ],

          "formatted": "<human-readable list of campaigns>",
          "message": "<status summary>"
        }
    """
    safe_limit, safe_offset = _validate_pagination(limit, offset)
    attack_data = get_attack_data(domain)

    resolved_id, tech_obj, err = _resolve_stix_object(
        technique_stix_id, domain=domain, expected_stix_type="attack-pattern"
    )
    if resolved_id is None:
        return {
            "found": False,
            "technique": None,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "campaigns": [],
            "formatted": "",
            "message": err or f"Technique '{technique_stix_id}' not found in domain '{domain}'.",
        }
    technique_stix_id = resolved_id

    technique_info: Optional[Dict[str, Any]] = None
    if tech_obj is not None:
        t_name = _stix_get(tech_obj, "name")
        t_desc = _stix_get(tech_obj, "description") if include_description else None
        try:
            t_attack_id = attack_data.get_attack_id(technique_stix_id)
        except Exception:
            t_attack_id = None

        technique_info = {
            "attack_id": t_attack_id,
            "name": t_name,
            "stix_id": technique_stix_id,
            "description": t_desc,
        }

    try:
        rel_entries = attack_data.get_campaigns_using_technique(technique_stix_id)
    except Exception:
        rel_entries = []

    if not rel_entries:
        return {
            "found": True,
            "technique": technique_info,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "campaigns": [],
            "formatted": "",
            "message": (
                f"No campaigns found using technique STIX ID "
                f"'{technique_stix_id}' in domain '{domain}'."
            ),
        }

    normalized_entries: List[Tuple[Tuple[int, str, str, str], Any, Optional[str], Optional[str], Optional[str], List[Any]]] = []

    for entry in rel_entries:
        if isinstance(entry, dict) and ("object" in entry or "relationships" in entry):
            camp_obj = entry.get("object", entry)
            rels = entry.get("relationships", [])
        else:
            camp_obj = entry
            rels = []

        if camp_obj is None:
            continue

        c_name = _stix_get(camp_obj, "name")
        c_stix_id = _stix_get(camp_obj, "id")
        try:
            c_attack_id = attack_data.get_attack_id(c_stix_id) if c_stix_id else None
        except Exception:
            c_attack_id = None

        normalized_entries.append(
            (_attack_id_sort_key(c_attack_id, c_name, c_stix_id), camp_obj, c_attack_id, c_name, c_stix_id, rels)
        )

    normalized_entries.sort(key=lambda item: item[0])
    page_entries, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        normalized_entries, limit=limit, offset=offset
    )

    campaigns_structured: List[Dict[str, Any]] = []
    campaign_objects_for_format: List[Any] = []

    for _sort_key, camp_obj, c_attack_id, c_name, c_stix_id, rels in page_entries:
        campaign_objects_for_format.append(camp_obj)
        c_aliases = _get_aliases(camp_obj)
        c_desc = _stix_get(camp_obj, "description") if include_description else None
        relationships_info = [_format_rel_edge(r, include_description=include_description) for r in rels]

        campaigns_structured.append(
            {
                "attack_id": c_attack_id,
                "name": c_name,
                "aliases": c_aliases,
                "stix_id": c_stix_id,
                "description": c_desc,
                "relationships": relationships_info,
            }
        )

    formatted = ""
    if include_formatted and campaign_objects_for_format:
        formatted = format_objects(
            campaign_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "found": True,
        "technique": technique_info,
        "count": len(campaigns_structured),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": next_offset,
        "campaigns": campaigns_structured,
        "formatted": formatted,
        "message": (
            f"Found {total_count} campaign(s) using technique "
            f"STIX ID '{technique_stix_id}' in domain '{domain}' "
            f"(returning {len(campaigns_structured)} at offset {safe_offset})."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_techniques_used_by_campaign(
    campaign_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
    limit: PageLimit = DEFAULT_PAGE_LIMIT,
    offset: PageOffset = 0,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Get all techniques used in a specific campaign.

    Accepts either a STIX ID ("campaign--UUID") or an ATT&CK ID (e.g., "C0024").

    Args:
        campaign_stix_id: Campaign STIX UUID ("campaign--UUID") or ATT&CK ID (e.g., "C0024").
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Whether to include technique descriptions.
        limit: Maximum number of items to return per page (1-200).
        offset: Zero-based starting index for pagination (>= 0).
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
          "found": bool,
          "campaign": {
              "attack_id": "CXXXX" | null,
              "name": "<campaign name or null>",
              "stix_id": "<campaign--UUID>",
              "description": "<text or null>",
          } | null,

          "count": <number of techniques in this page>,
          "total_count": <total number of techniques>,
          "offset": <offset>,
          "limit": <limit>,
          "has_more": <bool>,
          "next_offset": <int or null>,

          "techniques": [
            {
              "attack_id": "TXXXX or TXXXX.YYY" | null,
              "name": "<technique name>",
              "stix_id": "<attack-pattern--UUID>",
              "description": "<text or null>",
              "tactics": ["<Tactic 1>", "<Tactic 2>", ...],
              "relationships": [
                {
                  "stix_id": "<relationship--UUID>",
                  "relationship_type": "<type>",
                  "description": "<relationship description or null>",
                  "source_ref": "<source STIX ID>",
                  "target_ref": "<target STIX ID>",
                },
                ...
              ]
            },
            ...
          ],

          "formatted": "<human-readable list of techniques>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)
    safe_limit, safe_offset = _validate_pagination(limit, offset)

    resolved_id, camp_obj, err = _resolve_stix_object(
        campaign_stix_id, domain=domain, expected_stix_type="campaign"
    )
    if resolved_id is None:
        return {
            "found": False,
            "campaign": None,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "techniques": [],
            "formatted": "",
            "message": err or f"Campaign '{campaign_stix_id}' not found in domain '{domain}'.",
        }
    campaign_stix_id = resolved_id

    campaign_info: Optional[Dict[str, Any]] = None
    if camp_obj is not None:
        c_name = _stix_get(camp_obj, "name")
        c_desc = _stix_get(camp_obj, "description") if include_description else None
        try:
            c_attack_id = attack_data.get_attack_id(campaign_stix_id)
        except Exception:
            c_attack_id = None

        campaign_info = {
            "attack_id": c_attack_id,
            "name": c_name,
            "stix_id": campaign_stix_id,
            "description": c_desc,
        }

    try:
        rel_entries = attack_data.get_techniques_used_by_campaign(campaign_stix_id)
    except Exception:
        rel_entries = []

    if not rel_entries:
        return {
            "found": True,
            "campaign": campaign_info,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "techniques": [],
            "formatted": "",
            "message": (
                f"No techniques found for campaign STIX ID "
                f"'{campaign_stix_id}' in domain '{domain}'."
            ),
        }

    normalized_entries: List[Tuple[Any, List[Any]]] = []
    for entry in rel_entries:
        if isinstance(entry, dict) and ("object" in entry or "relationships" in entry):
            tech_obj = entry.get("object", entry)
            rels = entry.get("relationships", [])
        else:
            tech_obj = entry
            rels = []
        if tech_obj is not None:
            normalized_entries.append((tech_obj, rels))

    normalized_entries.sort(
        key=lambda pair: (
            str(_stix_get(pair[0], "name") or ""),
            str(_stix_get(pair[0], "id") or ""),
        )
    )
    page_entries, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        normalized_entries, limit=limit, offset=offset
    )

    techniques_structured: List[Dict[str, Any]] = []
    technique_objects_for_format: List[Any] = []

    for tech_obj, rels in page_entries:
        technique_objects_for_format.append(tech_obj)

        t_name = _stix_get(tech_obj, "name")
        t_stix_id = _stix_get(tech_obj, "id")
        t_desc = _stix_get(tech_obj, "description") if include_description else None
        tactics = _extract_tactic_names(tech_obj)

        try:
            t_attack_id = attack_data.get_attack_id(t_stix_id) if t_stix_id else None
        except Exception:
            t_attack_id = None

        relationships_info = [_format_rel_edge(r, include_description=include_description) for r in rels]

        techniques_structured.append(
            {
                "attack_id": t_attack_id,
                "name": t_name,
                "stix_id": t_stix_id,
                "description": t_desc,
                "tactics": tactics,
                "relationships": relationships_info,
            }
        )

    formatted = ""
    if include_formatted and technique_objects_for_format:
        formatted = format_objects(
            technique_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "found": True,
        "campaign": campaign_info,
        "count": len(techniques_structured),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": next_offset,
        "techniques": techniques_structured,
        "formatted": formatted,
        "message": (
            f"Found {total_count} technique(s) used by campaign "
            f"STIX ID '{campaign_stix_id}' in domain '{domain}' "
            f"(returning {len(techniques_structured)} at offset {safe_offset})."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_campaigns_using_software(
    software_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
    limit: PageLimit = DEFAULT_PAGE_LIMIT,
    offset: PageOffset = 0,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Get all campaigns that use specific software/malware, with pagination.

    This is a reverse lookup: Software → Campaigns, sorted deterministically by attack_id ascending.
    Accepts either a STIX ID ("malware--UUID", "tool--UUID") or an ATT&CK ID (e.g., "S0154").

    Args:
        software_stix_id: Software STIX UUID ("malware--UUID", "tool--UUID") or ATT&CK ID (e.g., "S0154").
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Whether to include campaign descriptions.
        limit: Maximum number of campaigns to return per page (1-200).
        offset: Zero-based starting index for pagination (>= 0).
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
          "found": bool,
          "software": {
              "attack_id": "SXXXX or similar" | null,
              "name": "<software name or null>",
              "stix_id": "<software STIX ID>",
              "type": "<malware|tool|...> or null",
              "description": "<text or null>",
          } | null,

          "count": <number of campaigns in this page>,
          "total_count": <total number of campaigns>,
          "offset": <page offset>,
          "limit": <page limit>,
          "has_more": bool,
          "next_offset": int | null,

          "campaigns": [
            {
              "attack_id": "CXXXX" | null,
              "name": "<campaign name>",
              "aliases": [...],
              "stix_id": "<campaign--UUID>",
              "description": "<text or null>",
              "relationships": [
                {
                  "stix_id": "<relationship--UUID>",
                  "relationship_type": "<type>",
                  "description": "<relationship description or null>",
                  "source_ref": "<source STIX ID>",
                  "target_ref": "<target STIX ID>",
                },
                ...
              ]
            },
            ...
          ],

          "formatted": "<human-readable list of campaigns>",
          "message": "<status summary>"
        }
    """
    safe_limit, safe_offset = _validate_pagination(limit, offset)
    attack_data = get_attack_data(domain)

    resolved_id, sw_obj, err = _resolve_stix_object(
        software_stix_id, domain=domain, expected_stix_type=("malware", "tool")
    )
    if resolved_id is None:
        return {
            "found": False,
            "software": None,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "campaigns": [],
            "formatted": "",
            "message": err or f"Software '{software_stix_id}' not found in domain '{domain}'.",
        }
    software_stix_id = resolved_id

    software_info = None
    if sw_obj is not None:
        s_name = _stix_get(sw_obj, "name")
        s_type = _stix_get(sw_obj, "type")
        s_desc = _stix_get(sw_obj, "description") if include_description else None
        try:
            s_attack_id = attack_data.get_attack_id(software_stix_id)
        except Exception:
            s_attack_id = None

        software_info = {
            "attack_id": s_attack_id,
            "name": s_name,
            "stix_id": software_stix_id,
            "type": s_type,
            "description": s_desc,
        }

    try:
        rel_entries = attack_data.get_campaigns_using_software(software_stix_id)
    except Exception:
        rel_entries = []

    if not rel_entries:
        return {
            "found": True,
            "software": software_info,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "campaigns": [],
            "formatted": "",
            "message": (
                f"No campaigns found using software STIX ID "
                f"'{software_stix_id}' in domain '{domain}'."
            ),
        }

    normalized_entries: List[Tuple[Tuple[int, str, str, str], Any, Optional[str], Optional[str], Optional[str], List[Any]]] = []

    for entry in rel_entries:
        if isinstance(entry, dict) and ("object" in entry or "relationships" in entry):
            camp_obj = entry.get("object", entry)
            rels = entry.get("relationships", [])
        else:
            camp_obj = entry
            rels = []

        if camp_obj is None:
            continue

        c_name = _stix_get(camp_obj, "name")
        c_stix_id = _stix_get(camp_obj, "id")
        try:
            c_attack_id = attack_data.get_attack_id(c_stix_id) if c_stix_id else None
        except Exception:
            c_attack_id = None

        normalized_entries.append(
            (_attack_id_sort_key(c_attack_id, c_name, c_stix_id), camp_obj, c_attack_id, c_name, c_stix_id, rels)
        )

    normalized_entries.sort(key=lambda item: item[0])
    page_entries, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        normalized_entries, limit=limit, offset=offset
    )

    campaigns_structured: List[Dict[str, Any]] = []
    campaign_objects_for_format: List[Any] = []

    for _sort_key, camp_obj, c_attack_id, c_name, c_stix_id, rels in page_entries:
        campaign_objects_for_format.append(camp_obj)
        c_aliases = _get_aliases(camp_obj)
        c_desc = _stix_get(camp_obj, "description") if include_description else None
        relationships_info = [_format_rel_edge(r, include_description=include_description) for r in rels]

        campaigns_structured.append(
            {
                "attack_id": c_attack_id,
                "name": c_name,
                "aliases": c_aliases,
                "stix_id": c_stix_id,
                "description": c_desc,
                "relationships": relationships_info,
            }
        )

    formatted = ""
    if include_formatted and campaign_objects_for_format:
        formatted = format_objects(
            campaign_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "found": True,
        "software": software_info,
        "count": len(campaigns_structured),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": next_offset,
        "campaigns": campaigns_structured,
        "formatted": formatted,
        "message": (
            f"Found {total_count} campaign(s) using software "
            f"STIX ID '{software_stix_id}' in domain '{domain}' "
            f"(returning {len(campaigns_structured)} at offset {safe_offset})."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_software_used_by_campaign(
    campaign_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Get all software/malware used in a specific campaign.

    Accepts either a STIX ID ("campaign--UUID") or an ATT&CK ID (e.g., "C0024").

    Args:
        campaign_stix_id: Campaign STIX UUID ('campaign--UUID') or ATT&CK ID (e.g., 'C0024').
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Whether to include software descriptions.
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
          "found": bool,
          "campaign": {
              "attack_id": "CXXXX" | null,
              "name": "<campaign name or null>",
              "stix_id": "<campaign--UUID>",
              "description": "<text or null>",
          } | null,

          "count": <number of software objects>,

          "software": [
            {
              "attack_id": "SXXXX or similar" | null,
              "name": "<software name>",
              "stix_id": "<malware--UUID or tool--UUID>",
              "type": "<malware|tool|...> or null",
              "aliases": ["...", "..."],
              "description": "<text or null>",
              "relationships": [
                {
                  "stix_id": "<relationship--UUID>",
                  "relationship_type": "<type>",
                  "description": "<relationship description or null>",
                  "source_ref": "<source STIX ID>",
                  "target_ref": "<target STIX ID>",
                },
                ...
              ]
            },
            ...
          ],

          "formatted": "<human-readable list of software>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)

    resolved_id, camp_obj, err = _resolve_stix_object(
        campaign_stix_id, domain=domain, expected_stix_type="campaign"
    )
    if resolved_id is None:
        return {
            "found": False,
            "campaign": None,
            "count": 0,
            "software": [],
            "formatted": "",
            "message": err or f"Campaign '{campaign_stix_id}' not found in domain '{domain}'.",
        }
    campaign_stix_id = resolved_id

    campaign_info = None
    if camp_obj is not None:
        c_name = _stix_get(camp_obj, "name")
        c_desc = _stix_get(camp_obj, "description") if include_description else None
        try:
            c_attack_id = attack_data.get_attack_id(campaign_stix_id)
        except Exception:
            c_attack_id = None

        campaign_info = {
            "attack_id": c_attack_id,
            "name": c_name,
            "stix_id": campaign_stix_id,
            "description": c_desc,
        }

    try:
        rel_entries = attack_data.get_software_used_by_campaign(campaign_stix_id)
    except Exception:
        rel_entries = []

    if not rel_entries:
        return {
            "found": True,
            "campaign": campaign_info,
            "count": 0,
            "software": [],
            "formatted": "",
            "message": (
                f"No software found for campaign STIX ID "
                f"'{campaign_stix_id}' in domain '{domain}'."
            ),
        }

    software_structured: List[Dict[str, Any]] = []
    software_objects_for_format: List[Any] = []

    for entry in rel_entries:
        if isinstance(entry, dict) and ("object" in entry or "relationships" in entry):
            sw_obj = entry.get("object", entry)
            rels = entry.get("relationships", [])
        else:
            sw_obj = entry
            rels = []

        if sw_obj is None:
            continue

        software_objects_for_format.append(sw_obj)

        s_name = _stix_get(sw_obj, "name")
        s_stix_id = _stix_get(sw_obj, "id")
        s_type = _stix_get(sw_obj, "type")
        s_aliases = _get_aliases(sw_obj)
        s_desc = _stix_get(sw_obj, "description") if include_description else None

        try:
            s_attack_id = attack_data.get_attack_id(s_stix_id) if s_stix_id else None
        except Exception:
            s_attack_id = None

        relationships_info = [_format_rel_edge(r, include_description=include_description) for r in rels]

        software_structured.append(
            {
                "attack_id": s_attack_id,
                "name": s_name,
                "stix_id": s_stix_id,
                "type": s_type,
                "aliases": s_aliases,
                "description": s_desc,
                "relationships": relationships_info,
            }
        )

    formatted = ""
    if include_formatted and software_objects_for_format:
        formatted = format_objects(
            software_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "found": True,
        "campaign": campaign_info,
        "count": len(software_structured),
        "software": software_structured,
        "formatted": formatted,
        "message": (
            f"Found {len(software_structured)} software object(s) used by campaign "
            f"STIX ID '{campaign_stix_id}' in domain '{domain}'."
        ),
    }

#####################################################################
    # Technique functions
#####################################################################

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_techniques_by_platform(
    platform: str,
    domain: str = "enterprise",
    include_description: bool = True,
    remove_revoked_deprecated: bool = True,
    limit: Annotated[
        int,
        Field(
            default=DEFAULT_PAGE_LIMIT,
            ge=1,
            le=MAX_PAGE_LIMIT,
            description=f"Maximum number of items to return per page (1-{MAX_PAGE_LIMIT}).",
        ),
    ] = DEFAULT_PAGE_LIMIT,
    offset: Annotated[
        int,
        Field(
            default=0,
            ge=0,
            description="Zero-based starting index for pagination (>= 0).",
        ),
    ] = 0,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Get all ATT&CK techniques that apply to a specific platform.

    Supports case-insensitive platform matching (e.g., 'linux' -> 'Linux') and
    common legacy aliases ('Azure AD' -> 'Identity Provider', 'Network' -> 'Network Devices').
    When no techniques match, returns `available_platforms` listing valid platform names
    for the requested domain and `suggested_platforms` mapping common real-world IT asset
    labels (e.g., 'QNAP'/'Synology'/'NAS' -> ['Linux', 'Network Devices'], 'Router'/'Wi-Fi'
    -> ['Network Devices'], 'Ubuntu' -> ['Linux'], 'AWS'/'Azure'/'GCP' -> ['IaaS', 'SaaS',
    'Identity Provider']) so callers can self-correct in one step without guessing.

    Args:
        platform: Platform name (e.g., 'Windows', 'Linux', 'macOS', 'Containers',
                  'IaaS', 'SaaS', 'Network Devices', 'ESXi', 'Identity Provider',
                  'Office Suite', 'PRE'). Matching is case-insensitive.
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Whether to include technique descriptions.

    Returns:
        {
          "platform": "<platform>",
          "count": <number>,
          "techniques": [
            {
              "attack_id": "Txxxx" or "Txxxx.xxx" or null,
              "name": "<technique name>",
              "stix_id": "<attack-pattern--UUID>",
              "description": "<text or null>"
            },
            ...
          ],
          "formatted": "<optional formatted string>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)
    platform_aliases = {
        "azure ad": "Identity Provider",
        "office 365": "Office Suite",
        "google workspace": "Office Suite",
        "network": "Network Devices",
    }
    raw_plat = (platform or "").strip()

    all_techs: List[Any] = []
    known_platforms: Dict[str, str] = {}
    try:
        all_techs = attack_data.get_techniques(
            remove_revoked_deprecated=remove_revoked_deprecated
        ) or []
        for t in all_techs:
            for p in (_stix_get(t, "x_mitre_platforms", []) or []):
                if p and str(p).strip():
                    ps = str(p).strip()
                    known_platforms[ps.lower()] = ps
    except Exception:
        all_techs = []
    available_platforms = sorted(set(known_platforms.values()))

    if not raw_plat:
        safe_limit, safe_offset = _validate_pagination(limit, offset)
        avail_str = ", ".join(available_platforms) if available_platforms else "none"
        return {
            "platform": "",
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "techniques": [],
            "available_platforms": available_platforms,
            "suggested_platforms": [],
            "formatted": "",
            "message": (
                f"No techniques found for platform '' "
                f"in domain '{domain}'. "
                f"Valid platforms for domain '{domain}': {avail_str}."
            ),
        }

    plat_norm = platform_aliases.get(raw_plat.lower(), raw_plat)

    # Resolve canonical platform casing and filter exact case-insensitively
    canonical_platform = known_platforms.get(plat_norm.lower(), plat_norm)
    target_plat_lower = canonical_platform.lower()
    techniques = [
        t for t in all_techs
        if any(
            (p or "").strip().lower() == target_plat_lower
            for p in (_stix_get(t, "x_mitre_platforms", []) or [])
        )
    ]

    if not techniques:
        safe_limit, safe_offset = _validate_pagination(limit, offset)
        avail_str = ", ".join(available_platforms) if available_platforms else "none"
        suggested_platforms = _suggest_attack_platforms(raw_plat, available_platforms)
        hint_clause = (
            f" Suggested ATT&CK platform(s) for '{raw_plat}': {', '.join(suggested_platforms)}."
            if suggested_platforms
            else ""
        )
        return {
            "platform": canonical_platform,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "techniques": [],
            "available_platforms": available_platforms,
            "suggested_platforms": suggested_platforms,
            "formatted": "",
            "message": (
                f"No techniques found for platform '{canonical_platform}' "
                f"in domain '{domain}'.{hint_clause} "
                f"Valid platforms for domain '{domain}': {avail_str}."
            ),
        }

    techniques_sorted = sorted(
        techniques,
        key=lambda t: (
            str(_stix_get(t, "name") or ""),
            str(_stix_get(t, "id") or ""),
        ),
    )
    page_techniques, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        techniques_sorted, limit=limit, offset=offset
    )

    structured = []
    for tech in page_techniques:
        if isinstance(tech, dict):
            t_name = tech.get("name")
            t_stix = tech.get("id")
            t_desc = tech.get("description") if include_description else None
        else:
            t_name = getattr(tech, "name", None)
            t_stix = getattr(tech, "id", None)
            t_desc = getattr(tech, "description", None) if include_description else None

        # external ATT&CK ID (Txxxx)
        try:
            t_attack = attack_data.get_attack_id(t_stix)
        except Exception:
            t_attack = None

        structured.append(
            {
                "attack_id": t_attack,
                "name": t_name,
                "stix_id": t_stix,
                "description": t_desc,
            }
        )

    # optional human-readable formatting
    formatted = (
        format_objects(
            page_techniques,
            include_description=include_description,
            domain=domain,
        )
        if include_formatted
        else ""
    )

    return {
        "platform": canonical_platform,
        "count": len(structured),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": next_offset,
        "techniques": structured,
        "formatted": formatted,
        "message": (
            f"Found {total_count} technique(s) applicable to platform "
            f"'{canonical_platform}' in domain '{domain}' "
            f"(returning {len(structured)} at offset {safe_offset})."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_parent_technique_of_subtechnique(
    technique_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Get the parent technique of a subtechnique.

    Accepts either a STIX ID ("attack-pattern--UUID") or an ATT&CK ID (e.g., "T1566.002").

    Args:
        technique_stix_id: STIX UUID or ATT&CK ID (e.g., "T1566.002") of the subtechnique.
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Whether to include the parent's description.
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
          "found": bool,
          "count": int,
          "subtechnique_stix_id": "...",
          "subtechnique_attack_id": "Txxxx.xxx" or null,
          "parent": {
              "attack_id": "Txxxx",
              "name": "...",
              "stix_id": "attack-pattern--UUID",
              "description": "..." | null
          } or null,
          "formatted": "<human readable description>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)

    resolved_id, _sub_obj, err = _resolve_stix_object(
        technique_stix_id, domain=domain, expected_stix_type="attack-pattern"
    )
    if resolved_id is None:
        return {
            "found": False,
            "count": 0,
            "subtechnique_stix_id": technique_stix_id,
            "subtechnique_attack_id": None,
            "parent": None,
            "formatted": "",
            "message": err or f"Subtechnique '{technique_stix_id}' not found in domain '{domain}'.",
        }
    technique_stix_id = resolved_id

    try:
        sub_attack_id = attack_data.get_attack_id(technique_stix_id)
    except Exception:
        sub_attack_id = None

    try:
        parent_raw = attack_data.get_parent_technique_of_subtechnique(technique_stix_id)
    except Exception:
        parent_raw = None

    if isinstance(parent_raw, list):
        parent_raw = parent_raw[0] if parent_raw else None

    if isinstance(parent_raw, str):
        parent_stix_id = parent_raw
        parent_obj = attack_data.get_object_by_stix_id(parent_stix_id)
    else:
        parent_obj = _unwrap_stix_object(parent_raw)
        parent_stix_id = _stix_get(parent_obj, "id") if parent_obj is not None else None

    if parent_obj is None or not parent_stix_id:
        return {
            "found": False,
            "count": 0,
            "subtechnique_stix_id": technique_stix_id,
            "subtechnique_attack_id": sub_attack_id,
            "parent": None,
            "formatted": "",
            "message": (
                f"No parent technique found — '{technique_stix_id}' "
                f"is not a subtechnique in domain '{domain}'."
            ),
        }

    parent_name = _stix_get(parent_obj, "name")
    parent_desc = _stix_get(parent_obj, "description") if include_description else None

    try:
        parent_attack_id = attack_data.get_attack_id(parent_stix_id)
    except Exception:
        parent_attack_id = None

    formatted = (
        format_objects(
            [parent_obj],
            include_description=include_description,
            domain=domain,
        )
        if include_formatted
        else ""
    )

    return {
        "found": True,
        "count": 1,
        "subtechnique_stix_id": technique_stix_id,
        "subtechnique_attack_id": sub_attack_id,
        "parent": {
            "attack_id": parent_attack_id,
            "name": parent_name,
            "stix_id": parent_stix_id,
            "description": parent_desc,
        },
        "formatted": formatted,
        "message": (
            f"Parent technique for subtechnique '{sub_attack_id}' is "
            f"'{parent_attack_id}' ({parent_name})."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_subtechniques_of_technique(
    technique_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = False,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Get all subtechniques of a parent technique.

    Accepts either a STIX ID ("attack-pattern--UUID") or an ATT&CK ID (e.g., "T1566").

    Args:
        technique_stix_id: STIX UUID or ATT&CK ID (e.g., "T1566") of the parent technique.
        domain: ATT&CK domain.
        include_description: Whether to include subtechnique descriptions.
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
          "found": bool,
          "parent": {
              "stix_id": "...",
              "attack_id": "...",
              "name": "..."
          } | null,
          "count": int,
          "subtechniques": [
              {
                  "attack_id": "...",
                  "name": "...",
                  "stix_id": "...",
                  "description": "..." | null
              },
              ...
          ],
          "formatted": "<multi-line string>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)

    resolved_id, parent_obj, err = _resolve_stix_object(
        technique_stix_id, domain=domain, expected_stix_type="attack-pattern"
    )
    if resolved_id is None:
        return {
            "found": False,
            "parent": None,
            "count": 0,
            "subtechniques": [],
            "formatted": "",
            "message": err or f"Technique '{technique_stix_id}' not found in domain '{domain}'.",
        }
    technique_stix_id = resolved_id

    try:
        parent_attack_id = attack_data.get_attack_id(technique_stix_id)
    except Exception:
        parent_attack_id = None

    parent_name = _stix_get(parent_obj, "name") if parent_obj is not None else None

    try:
        subs = attack_data.get_subtechniques_of_technique(technique_stix_id) or []
    except Exception:
        subs = []

    if not subs:
        return {
            "found": True,
            "parent": {
                "stix_id": technique_stix_id,
                "attack_id": parent_attack_id,
                "name": parent_name,
            },
            "count": 0,
            "subtechniques": [],
            "formatted": "",
            "message": (
                f"No subtechniques found for technique "
                f"'{parent_attack_id}' in domain '{domain}'."
            ),
        }

    sub_list = []
    unwrapped_subs = []
    for item in subs:
        obj = _unwrap_stix_object(item)
        if obj is None:
            continue
        unwrapped_subs.append(obj)
        stix_id = _stix_get(obj, "id")
        name = _stix_get(obj, "name")
        try:
            attack_id = attack_data.get_attack_id(stix_id) if stix_id else None
        except Exception:
            attack_id = None
        desc = _stix_get(obj, "description") if include_description else None

        sub_list.append(
            {
                "attack_id": attack_id,
                "name": name,
                "stix_id": stix_id,
                "description": desc,
            }
        )

    formatted = (
        format_objects(
            unwrapped_subs,
            include_description=include_description,
            domain=domain,
        )
        if include_formatted
        else ""
    )

    return {
        "found": True,
        "parent": {
            "stix_id": technique_stix_id,
            "attack_id": parent_attack_id,
            "name": parent_name,
        },
        "count": len(sub_list),
        "subtechniques": sub_list,
        "formatted": formatted,
        "message": (
            f"Found {len(sub_list)} subtechniques for "
            f"'{parent_attack_id}' ({parent_name})."
        ),
    }

# ---------------------------------------------------------------------------
# Mitigation → Technique mapping
# ---------------------------------------------------------------------------

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_techniques_mitigated_by_mitigation(
    mitigation_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = False,
    limit: PageLimit = DEFAULT_PAGE_LIMIT,
    offset: PageOffset = 0,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Get all techniques mitigated by a specific mitigation (by STIX ID or ATT&CK ID).

    Args:
        mitigation_stix_id: STIX UUID ("course-of-action--UUID") or ATT&CK ID (e.g., "M1051").
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Include technique descriptions in the output.
        limit: Maximum number of items to return per page (1-200).
        offset: Zero-based starting index for pagination (>= 0).
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
          "found": bool,
          "mitigation": {
              "attack_id": "...",
              "name": "...",
              "stix_id": "course-of-action--..."
          } | null,
          "count": int,
          "total_count": int,
          "offset": int,
          "limit": int,
          "has_more": bool,
          "next_offset": int | null,
          "techniques": [
              {
                  "attack_id": "Txxxx",
                  "name": "...",
                  "stix_id": "...",
                  "description": "...",
              },
              ...
          ],
          "formatted": "<multi-line text>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)
    safe_limit, safe_offset = _validate_pagination(limit, offset)

    resolved_id, mitigation_obj, err = _resolve_stix_object(
        mitigation_stix_id, domain=domain, expected_stix_type="course-of-action"
    )
    if resolved_id is None or mitigation_obj is None:
        return {
            "found": False,
            "mitigation": None,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "techniques": [],
            "formatted": "",
            "message": err or (
                f"Mitigation '{mitigation_stix_id}' not found in domain '{domain}'."
            ),
        }
    mitigation_stix_id = resolved_id

    mitigation_name = _stix_get(mitigation_obj, "name")
    try:
        mitigation_attack_id = attack_data.get_attack_id(mitigation_stix_id)
    except Exception:
        mitigation_attack_id = None

    try:
        techniques = attack_data.get_techniques_mitigated_by_mitigation(
            mitigation_stix_id
        ) or []
    except Exception:
        techniques = []

    if not techniques:
        return {
            "found": True,
            "mitigation": {
                "attack_id": mitigation_attack_id,
                "name": mitigation_name,
                "stix_id": mitigation_stix_id,
            },
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "techniques": [],
            "formatted": "",
            "message": (
                f"No techniques are mitigated by '{mitigation_attack_id}' "
                f"({mitigation_name}) in domain '{domain}'."
            ),
        }

    unwrapped_all = [
        t for t in (_unwrap_stix_object(item) for item in techniques) if t is not None
    ]
    unwrapped_sorted = sorted(
        unwrapped_all,
        key=lambda t: (
            str(_stix_get(t, "name") or ""),
            str(_stix_get(t, "id") or ""),
        ),
    )
    page_techs, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        unwrapped_sorted, limit=limit, offset=offset
    )

    technique_entries = []
    for t in page_techs:
        stix_id = _stix_get(t, "id")
        name = _stix_get(t, "name")
        desc = _stix_get(t, "description") if include_description else None

        try:
            attack_id = attack_data.get_attack_id(stix_id) if stix_id else None
        except Exception:
            attack_id = None

        technique_entries.append(
            {
                "attack_id": attack_id,
                "name": name,
                "stix_id": stix_id,
                "description": desc,
            }
        )

    formatted = (
        format_objects(
            page_techs,
            include_description=include_description,
            domain=domain,
        )
        if include_formatted
        else ""
    )

    return {
        "found": True,
        "mitigation": {
            "attack_id": mitigation_attack_id,
            "name": mitigation_name,
            "stix_id": mitigation_stix_id,
        },
        "count": len(technique_entries),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": next_offset,
        "techniques": technique_entries,
        "formatted": formatted,
        "message": (
            f"Found {total_count} techniques mitigated by "
            f"'{mitigation_attack_id}' ({mitigation_name}) "
            f"(returning {len(technique_entries)} at offset {safe_offset})."
        ),
    }


def _build_mitigation_batch_metadata(
    domain: str,
    include_description: bool,
    exists: Optional[bool] = None,
    detail_level: str = "compact",
) -> Dict[str, Any]:
    """Build version, source provenance, and coverage caveat metadata for batch mitigation responses."""
    if domain in DOMAINS:
        prov = _build_domain_provenance(domain, exists=exists)
    else:
        prov = {
            "loaded_version": None,
            "stix_spec_version": "2.1",
            "source_url": None,
            "source_repository": _SOURCE_REPOSITORY_URL,
            "source_release_date": None,
            "freshness_status": "invalid_domain",
        }
    meta: Dict[str, Any] = {
        "attack_version": prov.get("loaded_version") or str(release_info.LATEST_VERSION),
        "domain": domain,
        "source_url": prov.get("source_url"),
        "source_release_date": prov.get("source_release_date"),
        "freshness_status": prov.get("freshness_status"),
        "detail_level": detail_level,
        "max_batch_size": MAX_BATCH_DETECTION_TECHNIQUES,
        "caveat": _MITIGATION_COVERAGE_CAVEAT,
    }
    if detail_level == "full":
        meta["stix_spec_version"] = prov.get("stix_spec_version", "2.1")
        meta["source_repository"] = prov.get("source_repository", _SOURCE_REPOSITORY_URL)
        meta["include_description"] = bool(include_description)
    elif include_description:
        meta["include_description"] = bool(include_description)
    return meta


def _empty_mitigation_batch_coverage(detail_level: str = "compact") -> Dict[str, Any]:
    if detail_level == "compact":
        return {
            "mitigations": {},
            "edges": {
                "technique_to_mitigation": {},
            },
        }
    return {
        "mitigations": [],
        "edges": {
            "technique_to_mitigation": [],
        },
    }


def _get_mitigations_mitigating_technique_batch(
    technique_stix_id: str,
    technique_ids: Optional[List[str]],
    domain: str,
    include_description: bool,
    detail_level: str = "compact",
) -> Dict[str, Any]:
    """Deterministic, deduplicated batch mitigation lookup for multiple techniques."""
    dom = (domain or "enterprise").strip().lower()
    level = (
        (detail_level or "compact").strip().lower()
        if isinstance(detail_level, str)
        else str(detail_level).lower()
    )

    raw_tokens: List[str] = []
    if isinstance(technique_stix_id, str) and technique_stix_id.strip():
        raw_tokens.extend(part.strip() for part in technique_stix_id.split(","))
    if technique_ids is not None:
        for item in technique_ids:
            if isinstance(item, str):
                raw_tokens.extend(part.strip() for part in item.split(","))
            elif item is not None:
                raw_tokens.append(str(item).strip())

    non_empty_tokens = [tok for tok in raw_tokens if tok]
    requested_count = len(non_empty_tokens)

    unique_tokens: List[str] = []
    seen_tokens: set[str] = set()
    dup_tokens: set[str] = set()
    duplicates_removed_count = 0
    for tok in non_empty_tokens:
        canon = tok.lower() if "--" in tok else tok.upper()
        if canon in seen_tokens:
            dup_tokens.add(canon)
            duplicates_removed_count += 1
        else:
            seen_tokens.add(canon)
            unique_tokens.append(canon)

    def _error_response(
        error_code: str,
        message: str,
        techniques_list: Optional[List[Dict[str, Any]]] = None,
        exists: Optional[bool] = None,
    ) -> Dict[str, Any]:
        eff_level = level if level in _VALID_BATCH_DETAIL_LEVELS else "compact"
        tech_rows = techniques_list or []
        unavail_count = sum(1 for t in tech_rows if t.get("status") == "UNAVAILABLE")
        return {
            "found": False,
            "batch": True,
            "detail_level": eff_level,
            "domain": dom,
            "error_code": error_code,
            "count": 0,
            "counts": {
                "requested_inputs": requested_count,
                "unique_inputs": len(unique_tokens),
                "duplicates_removed": duplicates_removed_count,
                "techniques_total": len(tech_rows),
                "found": 0,
                "valid_no_mitigation": 0,
                "not_found": 0,
                "invalid": 0,
                "unavailable": unavail_count,
                "mitigations": 0,
            },
            "duplicates_removed": sorted(dup_tokens),
            "techniques": tech_rows,
            "coverage": _empty_mitigation_batch_coverage(eff_level),
            "metadata": _build_mitigation_batch_metadata(
                dom,
                include_description=include_description,
                exists=exists,
                detail_level=eff_level,
            ),
            "message": message,
        }

    if level not in _VALID_BATCH_DETAIL_LEVELS:
        return _error_response(
            "INVALID_DETAIL_LEVEL",
            f"Invalid detail_level '{detail_level}'. Must be one of: {', '.join(_VALID_BATCH_DETAIL_LEVELS)}.",
        )

    if dom not in DOMAINS:
        return _error_response(
            "INVALID_DOMAIN",
            f"Invalid domain '{dom}'. Must be one of: {', '.join(DOMAINS)}.",
        )

    if not unique_tokens:
        return _error_response(
            "EMPTY_INPUT",
            (
                "No technique IDs provided. Supply one or more ATT&CK technique IDs "
                "(e.g., 'T1190,T1203') or STIX IDs ('attack-pattern--<uuid>')."
            ),
        )

    if len(unique_tokens) > MAX_BATCH_DETECTION_TECHNIQUES:
        return _error_response(
            "BATCH_LIMIT_EXCEEDED",
            (
                f"Batch size {len(unique_tokens)} exceeds maximum allowed "
                f"{MAX_BATCH_DETECTION_TECHNIQUES} unique technique IDs per call."
            ),
        )

    stix_path = get_stix_path(dom)
    if not stix_path.exists():
        unavailable_rows = [
            {
                "input": tok,
                "matched_inputs": [tok],
                "status": "UNAVAILABLE",
                "attack_id": None,
                "name": None,
                "stix_id": None,
                "revoked": False,
                "deprecated": False,
                "mitigation_ids": [],
                "error": f"STIX data for domain '{dom}' is not available.",
            }
            for tok in sorted(unique_tokens)
        ]
        return _error_response(
            "DOMAIN_UNAVAILABLE",
            f"STIX data for domain '{dom}' is not available.",
            techniques_list=unavailable_rows,
            exists=False,
        )

    try:
        ad = get_attack_data(dom)
        mit_idx = _get_v20_mitigation_index(dom)
    except Exception as e:
        unavailable_rows = [
            {
                "input": tok,
                "matched_inputs": [tok],
                "status": "UNAVAILABLE",
                "attack_id": None,
                "name": None,
                "stix_id": None,
                "revoked": False,
                "deprecated": False,
                "mitigation_ids": [],
                "error": f"Failed to load mitigation data for domain '{dom}': {e}",
            }
            for tok in sorted(unique_tokens)
        ]
        return _error_response(
            "DOMAIN_UNAVAILABLE",
            f"Failed to load mitigation data for domain '{dom}': {e}",
            techniques_list=unavailable_rows,
            exists=False,
        )

    tech_by_stix_id = mit_idx.get("tech_by_stix_id", {})
    tech_by_attack_id = mit_idx.get("tech_by_attack_id", {})
    tech_aid_map = mit_idx.get("tech_attack_id_by_id", {})
    mit_by_id = mit_idx.get("mit_by_id", {})
    mit_aid_map = mit_idx.get("mit_attack_id_by_id", {})
    tech_to_mits = mit_idx.get("tech_to_mits", {})

    def _lookup_aid(cache_map: Dict[str, Optional[str]], stix_id: str) -> str:
        aid = cache_map.get(stix_id)
        if aid:
            return str(aid)
        try:
            resolved = ad.get_attack_id(stix_id)
            if resolved:
                return str(resolved)
        except Exception:
            pass
        return stix_id

    resolved_by_stix: Dict[str, Dict[str, Any]] = {}
    unresolved_rows: List[Dict[str, Any]] = []

    mit_cov: Dict[str, Dict[str, Any]] = {}
    edges_t_m: set[Tuple[str, str]] = set()

    for tok in unique_tokens:
        is_valid_syntax = bool(
            _TECHNIQUE_ATTACK_ID_RE.match(tok) or _TECHNIQUE_STIX_ID_RE.match(tok)
        )
        if not is_valid_syntax:
            unresolved_rows.append({
                "input": tok,
                "matched_inputs": [tok],
                "status": "INVALID",
                "attack_id": None,
                "name": None,
                "stix_id": None,
                "revoked": False,
                "deprecated": False,
                "mitigation_ids": [],
                "error": (
                    f"Malformed or non-technique identifier '{tok}'. "
                    "Expected Txxxx, Txxxx.xxx, or attack-pattern--<uuid>."
                ),
            })
            continue

        tech_obj = None
        resolved_id = None
        if "--" in tok:
            tech_obj = tech_by_stix_id.get(tok.lower())
        else:
            tech_obj = tech_by_attack_id.get(tok.upper())
        if tech_obj is not None:
            resolved_id = _stix_get(tech_obj, "id")
            err = None
        else:
            err = f"Technique '{tok}' not found in domain '{dom}'."
        if resolved_id is None:
            unresolved_rows.append({
                "input": tok,
                "matched_inputs": [tok],
                "status": "NOT_FOUND",
                "attack_id": tok if _TECHNIQUE_ATTACK_ID_RE.match(tok) else None,
                "name": None,
                "stix_id": tok if _TECHNIQUE_STIX_ID_RE.match(tok) else None,
                "revoked": False,
                "deprecated": False,
                "mitigation_ids": [],
                "error": err,
            })
            continue

        if resolved_id in resolved_by_stix:
            existing = resolved_by_stix[resolved_id]
            if tok not in existing["matched_inputs"]:
                existing["matched_inputs"].append(tok)
                existing["matched_inputs"].sort()
                existing["input"] = existing["matched_inputs"][0]
            dup_tokens.add(tok)
            duplicates_removed_count += 1
            continue

        tech_aid = tech_aid_map.get(resolved_id)
        if tech_aid is None:
            try:
                tech_aid = ad.get_attack_id(resolved_id)
            except Exception:
                tech_aid = None
        tech_key = str(tech_aid or resolved_id)
        tech_name = _stix_get(tech_obj, "name")
        is_revoked = bool(_stix_get(tech_obj, "revoked", False))
        is_deprecated = bool(_stix_get(tech_obj, "x_mitre_deprecated", False))

        t_m_ids: set[str] = set()
        for m_stix_id in tech_to_mits.get(resolved_id, []):
            m_obj = mit_by_id.get(m_stix_id)
            if m_obj is None:
                continue
            m_aid = _lookup_aid(mit_aid_map, m_stix_id)
            t_m_ids.add(m_aid)
            edges_t_m.add((tech_key, m_aid))

            m_entry = mit_cov.get(m_stix_id)
            if m_entry is None:
                m_entry = {
                    "attack_id": m_aid,
                    "name": _stix_get(m_obj, "name"),
                    "stix_id": m_stix_id,
                    "_technique_ids": set(),
                }
                if include_description:
                    m_entry["description"] = _stix_get(m_obj, "description")
                mit_cov[m_stix_id] = m_entry
            m_entry["_technique_ids"].add(tech_key)

        status = "FOUND" if t_m_ids else "VALID_NO_MITIGATION"
        resolved_by_stix[resolved_id] = {
            "input": tok,
            "matched_inputs": [tok],
            "status": status,
            "attack_id": tech_aid,
            "name": tech_name,
            "stix_id": resolved_id,
            "revoked": is_revoked,
            "deprecated": is_deprecated,
            "mitigation_ids": sorted(
                t_m_ids, key=lambda x: _attack_id_sort_key(x, "", "")
            ),
            "error": None,
        }

    resolved_rows = sorted(
        resolved_by_stix.values(),
        key=lambda r: _attack_id_sort_key(r["attack_id"], r["name"], r["stix_id"]),
    )
    status_rank = {"NOT_FOUND": 1, "INVALID": 2, "UNAVAILABLE": 3}
    unresolved_rows.sort(
        key=lambda r: (status_rank.get(r["status"], 9), str(r["input"]))
    )
    techniques_out = resolved_rows + unresolved_rows

    mit_out: List[Dict[str, Any]] = []
    for entry in sorted(
        mit_cov.values(),
        key=lambda x: _attack_id_sort_key(x["attack_id"], x["name"], x["stix_id"]),
    ):
        item: Dict[str, Any] = {
            "attack_id": entry["attack_id"],
            "name": entry["name"],
            "stix_id": entry["stix_id"],
            "technique_ids": sorted(
                entry["_technique_ids"], key=lambda x: _attack_id_sort_key(x, "", "")
            ),
        }
        if include_description:
            item["description"] = entry.get("description")
        mit_out.append(item)

    edges_out = {
        "technique_to_mitigation": [
            [t_id, m_id]
            for t_id, m_id in sorted(
                edges_t_m,
                key=lambda p: (
                    _attack_id_sort_key(p[0], "", ""),
                    _attack_id_sort_key(p[1], "", ""),
                ),
            )
        ]
    }

    found_count = sum(1 for r in techniques_out if r["status"] == "FOUND")
    no_mit_count = sum(1 for r in techniques_out if r["status"] == "VALID_NO_MITIGATION")
    not_found_count = sum(1 for r in techniques_out if r["status"] == "NOT_FOUND")
    invalid_count = sum(1 for r in techniques_out if r["status"] == "INVALID")
    unavail_count = sum(1 for r in techniques_out if r["status"] == "UNAVAILABLE")

    any_resolved = (found_count + no_mit_count) > 0

    if level == "compact":
        compact_techniques: List[Dict[str, Any]] = []
        for r in techniques_out:
            if r["status"] in ("FOUND", "VALID_NO_MITIGATION"):
                ct: Dict[str, Any] = {
                    "attack_id": r["attack_id"] or r["stix_id"],
                    "name": r["name"],
                    "status": r["status"],
                }
                if r["revoked"]:
                    ct["revoked"] = True
                if r["deprecated"]:
                    ct["deprecated"] = True
                if len(r["matched_inputs"]) > 1:
                    ct["matched_inputs"] = r["matched_inputs"]
                compact_techniques.append(ct)
            else:
                compact_techniques.append({
                    "input": r["input"],
                    "status": r["status"],
                    "error": r["error"],
                })

        compact_mit: Dict[str, Any] = {}
        for item in mit_out:
            if include_description:
                compact_mit[item["attack_id"]] = {
                    "name": item["name"],
                    "description": item.get("description"),
                }
            else:
                compact_mit[item["attack_id"]] = item["name"]

        adj_t_m: Dict[str, List[str]] = {}
        for src, dst in edges_out["technique_to_mitigation"]:
            adj_t_m.setdefault(src, []).append(dst)

        return {
            "found": any_resolved,
            "batch": True,
            "detail_level": "compact",
            "domain": dom,
            "count": len(mit_out),
            "counts": {
                "requested_inputs": requested_count,
                "unique_inputs": len(unique_tokens),
                "duplicates_removed": duplicates_removed_count,
                "techniques_total": len(techniques_out),
                "found": found_count,
                "valid_no_mitigation": no_mit_count,
                "not_found": not_found_count,
                "invalid": invalid_count,
                "unavailable": unavail_count,
                "mitigations": len(mit_out),
            },
            "duplicates_removed": sorted(dup_tokens),
            "techniques": compact_techniques,
            "coverage": {
                "mitigations": compact_mit,
                "edges": {
                    "technique_to_mitigation": adj_t_m,
                },
            },
            "metadata": _build_mitigation_batch_metadata(
                dom,
                include_description=include_description,
                exists=True,
                detail_level="compact",
            ),
            "message": (
                f"Resolved {found_count + no_mit_count} of {len(techniques_out)} technique(s) "
                f"in domain '{dom}': {len(mit_out)} unique mitigation(s)."
            ),
        }

    return {
        "found": any_resolved,
        "batch": True,
        "detail_level": "full",
        "domain": dom,
        "count": len(mit_out),
        "counts": {
            "requested_inputs": requested_count,
            "unique_inputs": len(unique_tokens),
            "duplicates_removed": duplicates_removed_count,
            "techniques_total": len(techniques_out),
            "found": found_count,
            "valid_no_mitigation": no_mit_count,
            "not_found": not_found_count,
            "invalid": invalid_count,
            "unavailable": unavail_count,
            "mitigations": len(mit_out),
        },
        "duplicates_removed": sorted(dup_tokens),
        "techniques": techniques_out,
        "coverage": {
            "mitigations": mit_out,
            "edges": edges_out,
        },
        "metadata": _build_mitigation_batch_metadata(
            dom,
            include_description=include_description,
            exists=True,
            detail_level="full",
        ),
        "message": (
            f"Resolved {found_count + no_mit_count} of {len(techniques_out)} technique(s) "
            f"in domain '{dom}': {len(mit_out)} unique mitigation(s)."
        ),
    }


@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_mitigations_mitigating_technique(
    technique_stix_id: str = "",
    domain: str = "enterprise",
    include_description: bool = False,
    include_formatted: bool = True,
    technique_ids: Optional[List[str]] = None,
    detail_level: BatchDetailLevel = "compact",
) -> Dict[str, Any]:
    """
    Get all mitigations (course-of-action, Mxxxx) that address one or more techniques.

    Single-technique mode (default when a single ID is passed via `technique_stix_id`
    and `technique_ids` is omitted):
      - Accepts a STIX ID ("attack-pattern--UUID") or ATT&CK ID (e.g., "T1190").
      - Preserves the exact single-technique response schema and formatted output.

    Batch mode (triggered when `technique_ids` is provided OR `technique_stix_id`
    contains comma-separated IDs such as "T1190,T1203,T1595.002"):
      - Accepts up to 50 unique technique IDs (ATT&CK IDs and/or STIX IDs).
      - Defaults to `detail_level='compact'` (token-efficient, deduplicated ID-indexed
        mitigation coverage map `Mxxxx -> name` and adjacency edges `T -> [M...]`,
        per-technique statuses, and provenance/caveat metadata).
      - Set `detail_level='full'` for full mitigation objects with STIX IDs and
        per-technique derived `mitigation_ids` lists.

    Args:
        technique_stix_id: Single technique STIX/ATT&CK ID (e.g., "T1190") or
            comma-separated technique IDs (e.g., "T1190,T1203,T1595.002").
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Include mitigation descriptions.
        include_formatted: If False, omits the human-readable formatted block in single mode.
        technique_ids: Optional list of technique STIX/ATT&CK IDs for batch lookup.
        detail_level: Batch detail level ('compact' default, or 'full'). Ignored in single mode.

    Returns (single-technique mode):
      {
        "found": bool,
        "technique": {...} | null,
        "count": int,
        "mitigations": [...],
        "formatted": str,
        "message": str
      }
    """
    is_batch = technique_ids is not None or (
        isinstance(technique_stix_id, str) and "," in technique_stix_id
    )
    if is_batch:
        return _get_mitigations_mitigating_technique_batch(
            technique_stix_id=technique_stix_id,
            technique_ids=technique_ids,
            domain=domain,
            include_description=include_description,
            detail_level=detail_level,
        )

    attack_data = get_attack_data(domain)

    resolved_id, technique_obj, err = _resolve_stix_object(
        technique_stix_id, domain=domain, expected_stix_type="attack-pattern"
    )
    if resolved_id is None:
        return {
            "found": False,
            "technique": None,
            "count": 0,
            "mitigations": [],
            "formatted": "",
            "message": err or f"Technique '{technique_stix_id}' not found in domain '{domain}'.",
        }
    technique_stix_id = resolved_id

    t_name = _stix_get(technique_obj, "name") if technique_obj is not None else None

    try:
        t_attack_id = attack_data.get_attack_id(technique_stix_id)
    except Exception:
        t_attack_id = None

    technique_info = {
        "attack_id": t_attack_id,
        "name": t_name,
        "stix_id": technique_stix_id,
    }

    try:
        rel_entries = attack_data.get_mitigations_mitigating_technique(technique_stix_id) or []
    except Exception:
        rel_entries = []

    if not rel_entries:
        return {
            "found": False,
            "technique": technique_info,
            "count": 0,
            "mitigations": [],
            "formatted": "",
            "message": (
                f"No mitigations found for technique STIX ID "
                f"'{technique_stix_id}' in domain '{domain}'."
            ),
        }

    mitigation_objects: List[Any] = []
    for e in rel_entries:
        m = _unwrap_stix_object(e)
        if m is None:
            continue
        mitigation_objects.append(m)

    mitigation_entries: List[Dict[str, Any]] = []
    for m in mitigation_objects:
        m_name = _stix_get(m, "name")
        m_stix = _stix_get(m, "id")
        m_desc = _stix_get(m, "description") if include_description else None

        try:
            m_attack_id = attack_data.get_attack_id(m_stix) if m_stix else None
        except Exception:
            m_attack_id = None

        mitigation_entries.append(
            {
                "attack_id": m_attack_id,
                "name": m_name,
                "stix_id": m_stix,
                "description": m_desc,
            }
        )

    formatted = (
        format_objects(
            mitigation_objects,
            include_description=include_description,
            domain=domain,
        )
        if include_formatted
        else ""
    )

    mitigation_entries = [
        x for x in mitigation_entries
        if x.get("name") or x.get("stix_id") or x.get("attack_id")
    ]

    return {
        "found": True,
        "technique": technique_info,
        "count": len(mitigation_entries),
        "mitigations": mitigation_entries,
        "formatted": formatted,
        "message": (
            f"Found {len(mitigation_entries)} mitigation(s) that address "
            f"technique '{technique_info.get('attack_id')}' "
            f"({technique_info.get('name')})."
        ),
    }


# ---------------------------------------------------------------------------
# Technique → Data components (detection)
# ---------------------------------------------------------------------------
@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
def get_datacomponents_detecting_technique(
    technique_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = False,
    include_formatted: bool = True,
) -> dict:
    """
    Get all data components that can detect a specific technique.

    Accepts either a STIX ID ("attack-pattern--UUID") or an ATT&CK ID (e.g., "T1059.001").

    Primary mode:
      - Use mitreattack-python relationship traversal (if present)

    Fallback mode (when relationship traversal yields 0):
      - Traverse ATT&CK v20.1 DetectionStrategy -> Analytic -> DataComponent graph
      - Fallback to legacy technique.x_mitre_data_sources strings if needed

    Args:
        technique_stix_id: Technique STIX ID ("attack-pattern--UUID") or ATT&CK ID (e.g., "T1059.001").
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Whether to include descriptions.
        include_formatted: If False, omits the human-readable formatted block to save tokens.
    """
    attack_data = get_attack_data(domain)

    resolved_id, tech_obj, err = _resolve_stix_object(
        technique_stix_id, domain=domain, expected_stix_type="attack-pattern"
    )
    if resolved_id is None:
        return {
            "found": False,
            "technique": None,
            "count": 0,
            "datacomponents": [],
            "detection_strategies": [],
            "formatted": "",
            "message": err or f"Technique '{technique_stix_id}' not found in domain '{domain}'.",
        }
    technique_stix_id = resolved_id

    def _get_attr(obj, name, default=None):
        if obj is None:
            return default
        if isinstance(obj, dict):
            return obj.get(name, default)
        return getattr(obj, name, default)

    def _technique_info(tech_obj) -> dict:
        attack_id = None
        name = _get_attr(tech_obj, "name")
        desc = _get_attr(tech_obj, "description")
        stix_id = _get_attr(tech_obj, "id")

        try:
            if stix_id:
                attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            attack_id = None

        return {
            "attack_id": attack_id,
            "name": name,
            "stix_id": stix_id,
            "description": desc if include_description else None,
        }

    technique_info = _technique_info(tech_obj) if tech_obj else None

    # ---------- 2) Primary: relationship-based lookup ----------
    datacomponents_structured: list[dict] = []
    debug = {
        "domain": domain,
        "query_mode": "relationship_first_then_fallback",
        "attack_id_used": technique_info["attack_id"] if technique_info else None,
        "stix_id_used": technique_stix_id,
    }

    try:
        rel_results = attack_data.get_datacomponents_detecting_technique(technique_stix_id)
        # Expected shape from mitreattack-python is often:
        #   [ { "object": <data-component>, "relationships": [<relationship>, ...] }, ... ]
        if isinstance(rel_results, list) and rel_results:
            for item in rel_results:
                if not isinstance(item, dict):
                    continue
                obj = item.get("object")
                rels = item.get("relationships", [])

                dc_name = _get_attr(obj, "name")
                dc_stix = _get_attr(obj, "id")
                dc_desc = _get_attr(obj, "description")

                ds_ref = _get_attr(obj, "x_mitre_data_source_ref")
                ds_name = None
                ds_attack_id = None
                if ds_ref:
                    try:
                        ds_obj = attack_data.get_object_by_stix_id(ds_ref)
                        ds_name = _get_attr(ds_obj, "name")
                        try:
                            ds_attack_id = attack_data.get_attack_id(ds_ref)
                        except Exception:
                            ds_attack_id = None
                    except Exception:
                        ds_name = None

                datacomponents_structured.append(
                    {
                        "name": dc_name,
                        "stix_id": dc_stix,
                        "description": dc_desc if include_description else None,
                        "data_source_stix_id": ds_ref,
                        "data_source_name": ds_name,
                        "data_source_attack_id": ds_attack_id,
                        "relationships": [
                            {
                                "stix_id": _get_attr(r, "id"),
                                "relationship_type": _get_attr(r, "relationship_type"),
                                "description": _get_attr(r, "description") if include_description else None,
                                "source_ref": _get_attr(r, "source_ref"),
                                "target_ref": _get_attr(r, "target_ref"),
                            }
                            for r in (rels if isinstance(rels, list) else [])
                        ],
                    }
                )

            debug["query_mode"] = "relationship_detects"
    except Exception:
        # ignore and fall back
        pass

    # ---------- 2b) ATT&CK v20.1 traversal: Technique <- DetectionStrategy -> Analytic -> DataComponent ----------
    detection_strategies_summary: list[dict] = []
    if not datacomponents_structured and tech_obj is not None:
        v20_idx = _get_v20_detection_index(domain)
        ds_ids = v20_idx["tech_to_ds"].get(technique_stix_id, [])
        for ds_id in ds_ids:
            ds_obj = v20_idx["ds_by_id"].get(ds_id)
            if ds_obj is None:
                continue
            try:
                ds_aid = attack_data.get_attack_id(ds_id)
            except Exception:
                ds_aid = None
            detection_strategies_summary.append({
                "attack_id": ds_aid,
                "name": _stix_get(ds_obj, "name"),
                "stix_id": ds_id,
                "analytic_count": len(_stix_get(ds_obj, "x_mitre_analytic_refs") or []),
            })
        dc_ids = v20_idx["tech_to_dcs"].get(technique_stix_id, [])
        for dc_id in dc_ids:
            dc_obj = v20_idx["dc_by_id"].get(dc_id)
            if dc_obj is None:
                continue
            try:
                dc_aid = attack_data.get_attack_id(dc_id)
            except Exception:
                dc_aid = None
            datacomponents_structured.append(
                {
                    "attack_id": dc_aid,
                    "name": _stix_get(dc_obj, "name"),
                    "stix_id": dc_id,
                    "description": _stix_get(dc_obj, "description") if include_description else None,
                    "data_source_stix_id": _stix_get(dc_obj, "x_mitre_data_source_ref"),
                    "data_source_name": None,
                    "data_source_attack_id": None,
                    "relationships": [],
                }
            )
        if datacomponents_structured:
            debug["query_mode"] = "v20_detection_strategy_analytic_graph"

    # ---------- 3) Fallback: x_mitre_data_sources mapping ----------
    if not datacomponents_structured and tech_obj is not None:
        debug["query_mode"] = "fallback_x_mitre_data_sources"

        # Example strings can look like:
        #   "Process: Process Creation"
        #   "Network Traffic: Network Connection Creation"
        #   or sometimes just "Process"
        x_mitre_data_sources = _get_attr(tech_obj, "x_mitre_data_sources", default=[]) or []

        # Build lookup maps
        try:
            datasources = attack_data.get_datasources(remove_revoked_deprecated=True)
        except Exception:
            datasources = []

        try:
            datacomponents_all = attack_data.get_datacomponents(remove_revoked_deprecated=True)
        except Exception:
            datacomponents_all = []

        ds_by_name = {}
        for ds in datasources or []:
            name = _get_attr(ds, "name")
            if isinstance(name, str):
                ds_by_name[name.strip().lower()] = ds

        # index components by parent datasource ref
        comps_by_ds_ref = {}
        for dc in datacomponents_all or []:
            ds_ref = _get_attr(dc, "x_mitre_data_source_ref")
            if not ds_ref:
                continue
            comps_by_ds_ref.setdefault(ds_ref, []).append(dc)

        def _parse_ds_string(s: str) -> tuple[str, str | None]:
            # "Process: Process Creation" -> ("Process", "Process Creation")
            if ":" in s:
                left, right = s.split(":", 1)
                return left.strip(), right.strip() if right.strip() else None
            return s.strip(), None

        for ds_str in x_mitre_data_sources:
            if not isinstance(ds_str, str) or not ds_str.strip():
                continue
            ds_name, component_name = _parse_ds_string(ds_str)

            ds_obj = ds_by_name.get(ds_name.lower())
            if ds_obj is None:
                continue

            ds_stix = _get_attr(ds_obj, "id")
            ds_attack_id = None
            try:
                if ds_stix:
                    ds_attack_id = attack_data.get_attack_id(ds_stix)
            except Exception:
                ds_attack_id = None

            candidates = comps_by_ds_ref.get(ds_stix, [])
            if component_name:
                # filter down if component specified
                filtered = []
                for dc in candidates:
                    n = _get_attr(dc, "name")
                    if isinstance(n, str) and n.strip().lower() == component_name.lower():
                        filtered.append(dc)
                # if nothing matched strictly, keep all candidates (better than returning nothing)
                candidates = filtered or candidates

            for dc in candidates:
                dc_name = _get_attr(dc, "name")
                dc_stix = _get_attr(dc, "id")
                dc_desc = _get_attr(dc, "description")

                datacomponents_structured.append(
                    {
                        "name": dc_name,
                        "stix_id": dc_stix,
                        "description": dc_desc if include_description else None,
                        "data_source_stix_id": ds_stix,
                        "data_source_name": _get_attr(ds_obj, "name"),
                        "data_source_attack_id": ds_attack_id,
                        "relationships": [],  # fallback mode: not relationship-derived
                    }
                )

        # de-dup by stix_id
        seen = set()
        deduped = []
        for dc in datacomponents_structured:
            sid = dc.get("stix_id")
            if sid and sid in seen:
                continue
            if sid:
                seen.add(sid)
            deduped.append(dc)
        datacomponents_structured = deduped

    # ---------- 4) formatted (optional) ----------
    formatted = ""
    if include_formatted and datacomponents_structured:
        formatted_lines = []
        for dc in datacomponents_structured:
            ds_part = f" ({dc['data_source_name']})" if dc.get("data_source_name") else ""
            formatted_lines.append(f"- {dc.get('name')}{ds_part}")
        formatted = "\n".join(formatted_lines)

    message = (
        f"Found {len(datacomponents_structured)} data component(s) that can detect "
        f"technique STIX ID '{technique_stix_id}' in domain '{domain}'."
        if datacomponents_structured
        else (
            "No data components found for this technique in this ATT&CK release. "
            "This can happen if relationship-based detection mappings are missing; "
            "fallback may also be empty if x_mitre_data_sources is absent."
        )
    )

    return {
        "found": True,
        "technique": technique_info,
        "count": len(datacomponents_structured),
        "datacomponents": datacomponents_structured,
        "detection_strategies": detection_strategies_summary,
        "formatted": formatted,
        "message": message,
    }


@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_techniques_detected_by_datacomponent(
    datacomponent_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
    limit: PageLimit = DEFAULT_PAGE_LIMIT,
    offset: PageOffset = 0,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Get all techniques that can be detected by a specific data component.

    Shows which adversary techniques can be identified by monitoring
    this specific aspect of telemetry. Accepts either a STIX ID
    ("x-mitre-data-component--UUID") or an ATT&CK ID (e.g., "DC0032").

    Args:
        datacomponent_stix_id: Data component STIX UUID ('x-mitre-data-component--UUID')
                               or ATT&CK ID (e.g., 'DC0032').
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Whether to include technique descriptions.
        limit: Maximum number of items to return per page (1-200).
        offset: Zero-based starting index for pagination (>= 0).
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
          "found": bool,
          "datacomponent": {
              "attack_id": "<DCxxxx or null>",
              "name": "<data component name or null>",
              "stix_id": "<x-mitre-data-component--UUID>",
              "description": "<text or null>",
              "data_source_stix_id": "<x-mitre-data-source--UUID or null>",
              "data_source_name": "<data source name or null>",
              "data_source_attack_id": "<data source ATT&CK ID or null>",
          } | null,

          "count": <number of techniques in this page>,
          "total_count": <total number of techniques>,
          "offset": <offset>,
          "limit": <limit>,
          "has_more": <bool>,
          "next_offset": <int or null>,

          "techniques": [
            {
              "attack_id": "Txxxx or Txxxx.xxx" | null,
              "name": "<technique name>",
              "stix_id": "<attack-pattern--UUID>",
              "description": "<text or null>",
            },
            ...
          ],

          "formatted": "<human-readable list of techniques>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)
    safe_limit, safe_offset = _validate_pagination(limit, offset)

    resolved_id, dc_obj, err = _resolve_stix_object(
        datacomponent_stix_id, domain=domain, expected_stix_type="x-mitre-data-component"
    )
    if resolved_id is None:
        return {
            "found": False,
            "datacomponent": None,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "techniques": [],
            "formatted": "",
            "message": err or f"Data component '{datacomponent_stix_id}' not found in domain '{domain}'.",
        }
    datacomponent_stix_id = resolved_id

    datacomponent_info: Optional[Dict[str, Any]] = None
    if dc_obj is not None:
        dc_name = _stix_get(dc_obj, "name")
        dc_desc = _stix_get(dc_obj, "description") if include_description else None
        ds_ref = _stix_get(dc_obj, "x_mitre_data_source_ref") or _stix_get(dc_obj, "x-mitre-data-source-ref")

        data_source_stix_id = ds_ref
        data_source_name = None
        data_source_attack_id = None

        if ds_ref:
            try:
                ds_obj = attack_data.get_object_by_stix_id(ds_ref)
            except Exception:
                ds_obj = None

            if ds_obj is not None:
                data_source_name = _stix_get(ds_obj, "name")
                ds_internal_id = _stix_get(ds_obj, "id")
                try:
                    data_source_attack_id = attack_data.get_attack_id(ds_internal_id) if ds_internal_id else None
                except Exception:
                    data_source_attack_id = None

        try:
            dc_attack_id = attack_data.get_attack_id(datacomponent_stix_id)
        except Exception:
            dc_attack_id = None

        datacomponent_info = {
            "attack_id": dc_attack_id,
            "name": dc_name,
            "stix_id": datacomponent_stix_id,
            "description": dc_desc,
            "data_source_stix_id": data_source_stix_id,
            "data_source_name": data_source_name,
            "data_source_attack_id": data_source_attack_id,
        }

    try:
        techniques = attack_data.get_techniques_detected_by_datacomponent(
            datacomponent_stix_id
        ) or []
    except Exception:
        techniques = []

    if not techniques:
        v20_idx = _get_v20_detection_index(domain)
        for tid in v20_idx["dc_to_techs"].get(datacomponent_stix_id, []):
            try:
                tobj = attack_data.get_object_by_stix_id(tid)
                if tobj is not None and not _stix_get(tobj, "revoked", False) and not _stix_get(tobj, "x_mitre_deprecated", False):
                    techniques.append(tobj)
            except Exception:
                continue

    if not techniques:
        return {
            "found": True,
            "datacomponent": datacomponent_info,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "techniques": [],
            "formatted": "",
            "message": (
                f"No techniques found that are detected by data component "
                f"STIX ID '{datacomponent_stix_id}' in domain '{domain}'."
            ),
        }

    techniques_sorted = sorted(
        techniques,
        key=lambda t: (
            str(_stix_get(t, "name") or ""),
            str(_stix_get(t, "id") or ""),
        ),
    )
    page_techniques, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        techniques_sorted, limit=limit, offset=offset
    )

    technique_entries: List[Dict[str, Any]] = []
    for t in page_techniques:
        t_name = _stix_get(t, "name")
        t_stix = _stix_get(t, "id")
        t_desc = _stix_get(t, "description") if include_description else None
        try:
            t_attack_id = attack_data.get_attack_id(t_stix) if t_stix else None
        except Exception:
            t_attack_id = None

        technique_entries.append(
            {
                "attack_id": t_attack_id,
                "name": t_name,
                "stix_id": t_stix,
                "description": t_desc,
            }
        )

    formatted = ""
    if include_formatted and page_techniques:
        formatted = format_objects(
            page_techniques,
            include_description=include_description,
            domain=domain,
        )

    return {
        "found": True,
        "datacomponent": datacomponent_info,
        "count": len(technique_entries),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": next_offset,
        "techniques": technique_entries,
        "formatted": formatted,
        "message": (
            f"Found {total_count} technique(s) that can be detected by "
            f"data component STIX ID '{datacomponent_stix_id}' in domain '{domain}' "
            f"(returning {len(technique_entries)} at offset {safe_offset})."
        ),
    }

# ---------------------------------------------------------------------------
# Technique → Tactic → Procedure Examples (real-world usage)
# ---------------------------------------------------------------------------

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_procedure_examples_by_technique(
    technique_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
    limit: PageLimit = DEFAULT_PAGE_LIMIT,
    offset: PageOffset = 0,
    include_formatted: bool = True,
    query: Annotated[
        str,
        Field(
            default="",
            description=(
                "Optional case-insensitive substring filter across procedure description "
                "and source name, ATT&CK ID, or STIX ID (e.g. 'CVE-', 'QNAP', 'SSH', 'G0016')."
            ),
        ),
    ] = "",
) -> Dict[str, Any]:
    """
    Get procedure examples showing how threat groups, software, or campaigns used a specific technique.

    Procedure examples describe real incident behavior tied to this technique.
    Accepts either a STIX ID ("attack-pattern--UUID") or an ATT&CK ID (e.g., "T1190").
    Results are deterministically sorted by source ATT&CK ID (then name, then STIX ID)
    and support pagination and optional case-insensitive substring filtering via `query`.

    Args:
        technique_stix_id: STIX UUID ("attack-pattern--UUID") or ATT&CK ID (e.g., "T1190").
        domain: ATT&CK domain.
        include_description: Include descriptions of the examples if available.
        limit: Maximum number of items to return per page (1-200).
        offset: Zero-based starting index for pagination (>= 0).
        include_formatted: If False, omits the human-readable formatted block to save tokens.
        query: Optional case-insensitive substring filter matching procedure description
               and source name/ID (e.g., "CVE-", "QNAP", "SSH").

    Returns:
        {
          "found": bool,
          "technique": {
              "attack_id": "Txxxx",
              "name": "...",
              "stix_id": "attack-pattern--UUID"
          } | null,
          "count": int,
          "total_count": int,
          "offset": int,
          "limit": int,
          "has_more": bool,
          "next_offset": int | null,
          "examples": [...],
          "formatted": "<multi-line readable text>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)
    safe_limit, safe_offset = _validate_pagination(limit, offset)
    query_clean = (query or "").strip()
    query_lower = query_clean.lower()

    resolved_id, tech_obj, err = _resolve_stix_object(
        technique_stix_id, domain=domain, expected_stix_type="attack-pattern"
    )
    if resolved_id is None:
        return {
            "found": False,
            "technique": None,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "examples": [],
            "formatted": "",
            "message": err or f"Technique '{technique_stix_id}' not found in domain '{domain}'.",
        }
    technique_stix_id = resolved_id

    tech_name = _stix_get(tech_obj, "name") if tech_obj is not None else None
    try:
        tech_attack_id = attack_data.get_attack_id(technique_stix_id)
    except Exception:
        tech_attack_id = None

    technique_info = {
        "attack_id": tech_attack_id,
        "name": tech_name,
        "stix_id": technique_stix_id,
    }

    try:
        examples = attack_data.get_procedure_examples_by_technique(
            technique_stix_id
        ) or []
    except Exception:
        examples = []

    query_suffix = f" matching query '{query_clean}'" if query_clean else ""

    if not examples:
        return {
            "found": True,
            "technique": technique_info,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "examples": [],
            "formatted": "",
            "message": (
                f"No procedure examples found for technique '{tech_attack_id}' "
                f"in domain '{domain}'{query_suffix}."
            ),
        }

    # Resolve source metadata before filtering and deterministic sorting by source attack_id
    source_cache: Dict[str, Tuple[Optional[str], Optional[str], Optional[str]]] = {}
    resolved_rows: List[Dict[str, Any]] = []
    for rel in examples:
        rel_id = _stix_get(rel, "id")
        raw_desc = _stix_get(rel, "description")
        source_stix_id = _stix_get(rel, "source_ref")

        if isinstance(source_stix_id, str) and source_stix_id in source_cache:
            src_attack_id, src_name, src_type = source_cache[source_stix_id]
        else:
            src_attack_id = None
            src_name = None
            src_type = (
                source_stix_id.split("--")[0]
                if isinstance(source_stix_id, str) and "--" in source_stix_id
                else None
            )
            try:
                src_obj = attack_data.get_object_by_stix_id(source_stix_id)
                if src_obj:
                    src_name = _stix_get(src_obj, "name")
                    src_type = _stix_get(src_obj, "type") or src_type
                    src_attack_id = attack_data.get_attack_id(source_stix_id)
            except Exception:
                pass
            if isinstance(source_stix_id, str):
                source_cache[source_stix_id] = (src_attack_id, src_name, src_type)

        if query_lower:
            haystack = (
                f"{raw_desc or ''}\n"
                f"{src_name or ''}\n"
                f"{src_attack_id or ''}\n"
                f"{source_stix_id or ''}"
            ).lower()
            if query_lower not in haystack:
                continue

        resolved_rows.append(
            {
                "rel_id": rel_id,
                "raw_desc": raw_desc,
                "source_stix_id": source_stix_id,
                "src_attack_id": src_attack_id,
                "src_name": src_name,
                "src_type": src_type,
            }
        )

    if not resolved_rows:
        return {
            "found": True,
            "technique": technique_info,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "examples": [],
            "formatted": "",
            "message": (
                f"No procedure examples found for technique '{tech_attack_id}' "
                f"in domain '{domain}'{query_suffix}."
            ),
        }

    resolved_rows.sort(
        key=lambda row: (
            _attack_id_sort_key(
                row["src_attack_id"],
                row["src_name"],
                row["source_stix_id"],
            ),
            str(row["rel_id"] or ""),
        )
    )

    page_rows, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        resolved_rows, limit=limit, offset=offset
    )

    example_entries = []
    for row in page_rows:
        rel_id = row["rel_id"]
        desc = row["raw_desc"] if include_description else None
        source_stix_id = row["source_stix_id"]
        src_attack_id = row["src_attack_id"]
        src_name = row["src_name"]
        src_type = row["src_type"]

        is_group = src_type == "intrusion-set"
        example_entries.append(
            {
                "relationship_id": rel_id,
                "source_type": src_type,
                "source": {
                    "attack_id": src_attack_id,
                    "name": src_name,
                    "stix_id": source_stix_id,
                    "type": src_type,
                },
                "source_group_attack_id": src_attack_id if is_group else None,
                "source_group_name": src_name if is_group else None,
                "description": desc,
                "stix_id": rel_id,
            }
        )

    formatted = ""
    if include_formatted:
        fmt_lines = []
        for e in example_entries:
            s = e["source"]
            label = f"[{s.get('type') or 'unknown'}] {s.get('name') or s.get('stix_id')}"
            if s.get("attack_id"):
                label += f" ({s['attack_id']})"
            if include_description and e.get("description"):
                fmt_lines.append(f"- {label}: {e['description']}")
            else:
                fmt_lines.append(f"- {label}")
        formatted = "\n".join(fmt_lines)

    return {
        "found": True,
        "technique": technique_info,
        "count": len(example_entries),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": next_offset,
        "examples": example_entries,
        "formatted": formatted,
        "message": (
            f"Found {total_count} procedure examples for "
            f"technique '{tech_attack_id}' ({tech_name}){query_suffix} "
            f"(returning {len(example_entries)} at offset {safe_offset})."
        ),
    }


@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_procedure_examples_by_tactic(
    tactic: str,
    domain: str = "enterprise",
    include_description: bool = True,
    limit: Annotated[
        int,
        Field(
            default=DEFAULT_PAGE_LIMIT,
            ge=1,
            le=MAX_PAGE_LIMIT,
            description=f"Maximum number of items to return per page (1-{MAX_PAGE_LIMIT}).",
        ),
    ] = DEFAULT_PAGE_LIMIT,
    offset: Annotated[
        int,
        Field(
            default=0,
            ge=0,
            description="Zero-based starting index for pagination (>= 0).",
        ),
    ] = 0,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Get all procedure examples for techniques in a specific tactic.

    Shows real-world examples of how threat groups use techniques that fall
    under a given tactic (e.g., Initial Access, Persistence).

    Args:
        tactic: Tactic name (e.g., "Initial Access", "Persistence").
                Case-insensitive; should match ATT&CK tactic names.
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Include example descriptions when available.

    Returns:
        {
          "tactic": {
              "name": "<tactic name>",
              "attack_id": "TAxxxx" | null,
              "stix_id": "x-mitre-tactic--UUID" | null,
          },
          "count": int,
          "examples": [
            {
              "relationship_id": "relationship--UUID",
              "description": "<procedure text or null>",
              "group": {
                "attack_id": "Gxxxx" | null,
                "name": "<group name or null>",
                "stix_id": "intrusion-set--UUID" | null,
              },
              "technique": {
                "attack_id": "Txxxx or Txxxx.xxx" | null,
                "name": "<technique name or null>",
                "stix_id": "attack-pattern--UUID" | null,
              },
            },
            ...
          ],
          "formatted": "<multi-line human-readable text>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # --- Resolve tactic metadata by name (best-effort) ---
    tactic_name_input = tactic
    tactic_name_norm = tactic.lower()
    tactic_stix_id = None
    tactic_attack_id = None

    try:
        all_tactics = attack_data.get_tactics(remove_revoked_deprecated=True)
    except Exception:
        all_tactics = []

    tactic_shortname = _normalize_tactic_shortname(attack_data, tactic)
    for t in all_tactics:
        t_name = (_stix_get(t, "name", "") or "").strip()
        t_short = (_stix_get(t, "x_mitre_shortname", "") or "").strip()
        if tactic_name_norm in {t_name.lower(), t_short.lower()} or tactic_shortname == t_short.lower():
            tactic_stix_id = _stix_get(t, "id")
            try:
                tactic_attack_id = attack_data.get_attack_id(tactic_stix_id)
            except Exception:
                tactic_attack_id = None
            tactic_name_input = t_name or tactic_name_input
            if t_short:
                tactic_shortname = t_short
            break

    tactic_info = {
        "name": tactic_name_input,
        "attack_id": tactic_attack_id,
        "stix_id": tactic_stix_id,
    }

    # --- Aggregate procedure examples across all techniques in this tactic ---
    examples = []
    seen_rel_ids = set()
    try:
        tactic_techniques = attack_data.get_techniques_by_tactic(
            tactic_shortname,
            f"{domain}-attack",
            remove_revoked_deprecated=True,
        ) or []
        for tech in tactic_techniques:
            tech_id = _stix_get(tech, "id")
            if not tech_id:
                continue
            for rel in attack_data.get_procedure_examples_by_technique(tech_id) or []:
                rel_obj = _unwrap_stix_object(rel)
                rel_id = _stix_get(rel_obj, "id")
                if rel_id and rel_id in seen_rel_ids:
                    continue
                if rel_id:
                    seen_rel_ids.add(rel_id)
                examples.append(rel_obj)
    except Exception:
        examples = []

    if not examples:
        legacy = _LEGACY_TACTIC_MIGRATIONS.get((tactic or "").strip().lower())
        msg = (
            f"No procedure examples found for tactic '{tactic_name_input}' "
            f"in domain '{domain}'."
        )
        safe_limit, safe_offset = _validate_pagination(limit, offset)
        resp: Dict[str, Any] = {
            "tactic": tactic_info,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "examples": [],
            "formatted": "",
            "message": f"{msg} {legacy['hint']}" if legacy else msg,
        }
        if legacy:
            resp["suggested_tactics"] = legacy["suggested_tactics"]
        return resp

    examples.sort(
        key=lambda r: (
            str(_stix_get(r, "id") or ""),
            str(_stix_get(r, "source_ref") or ""),
            str(_stix_get(r, "target_ref") or ""),
        )
    )
    page_examples, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        examples, limit=limit, offset=offset
    )

    example_entries: list[Dict[str, Any]] = []

    for rel in page_examples:
        # Relationship itself (procedure example)
        rel_id = _stix_get(rel, "id")
        rel_desc = _stix_get(rel, "description") if include_description else None
        source_ref = _stix_get(rel, "source_ref")
        target_ref = _stix_get(rel, "target_ref")

        # Resolve source entity (intrusion-set, malware, tool, or campaign)
        src_type = source_ref.split("--")[0] if isinstance(source_ref, str) and "--" in source_ref else None
        source_info = {
            "attack_id": None,
            "name": None,
            "stix_id": source_ref,
            "type": src_type,
        }
        if source_ref:
            try:
                g_obj = attack_data.get_object_by_stix_id(source_ref)
            except Exception:
                g_obj = None

            if g_obj is not None:
                g_name = _stix_get(g_obj, "name")
                src_type = _stix_get(g_obj, "type") or src_type
                try:
                    g_attack_id = attack_data.get_attack_id(source_ref)
                except Exception:
                    g_attack_id = None

                source_info = {
                    "attack_id": g_attack_id,
                    "name": g_name,
                    "stix_id": source_ref,
                    "type": src_type,
                }
        group_info = source_info if src_type == "intrusion-set" else None

        # Resolve target technique
        technique_info = {
            "attack_id": None,
            "name": None,
            "stix_id": target_ref,
        }
        if target_ref:
            try:
                tech_obj = attack_data.get_object_by_stix_id(target_ref)
            except Exception:
                tech_obj = None

            if tech_obj is not None:
                t_name = getattr(tech_obj, "name", None)
                try:
                    t_attack_id = attack_data.get_attack_id(target_ref)
                except Exception:
                    t_attack_id = None

                technique_info = {
                    "attack_id": t_attack_id,
                    "name": t_name,
                    "stix_id": target_ref,
                }

        example_entries.append(
            {
                "relationship_id": rel_id,
                "description": rel_desc,
                "source_type": src_type,
                "source": source_info,
                "group": group_info,
                "technique": technique_info,
            }
        )

    # --- Human-readable formatted block (for LLMs / humans) ---
    formatted = ""
    if include_formatted:
        fmt_lines = []
        for e in example_entries:
            s = e["source"]
            t = e["technique"]
            src_label = f"[{s.get('type') or 'unknown'}] {s.get('name') or s.get('stix_id')}"
            if s.get("attack_id"):
                src_label += f" ({s['attack_id']})"
            tech_label = t.get("name") or t.get("stix_id") or "unknown"
            if t.get("attack_id"):
                tech_label += f" ({t['attack_id']})"
            line = f"- {src_label} -> {tech_label}"
            if include_description and e.get("description"):
                line += f": {e['description']}"
            fmt_lines.append(line)
        formatted = "\n".join(fmt_lines)
    has_more = (safe_offset + len(example_entries)) < total_count

    return {
        "tactic": tactic_info,
        "count": len(example_entries),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": safe_offset + len(example_entries) if has_more else None,
        "examples": example_entries,
        "formatted": formatted,
        "message": (
            f"Showing {len(example_entries)} of {total_count} procedure example(s) "
            f"(offset={safe_offset}) for tactic '{tactic_info['name']}' in domain '{domain}'."
        ),
    }


# ---------------------------------------------------------------------------
# Generic STIX object browser
# ---------------------------------------------------------------------------

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_objects_by_type(
    stix_type: str,
    domain: str = "enterprise",
    remove_revoked_deprecated: bool = True,
    include_description: bool = False,
    limit: Annotated[
        int,
        Field(
            default=DEFAULT_PAGE_LIMIT,
            ge=1,
            le=MAX_PAGE_LIMIT,
            description=f"Maximum number of items to return per page (1-{MAX_PAGE_LIMIT}).",
        ),
    ] = DEFAULT_PAGE_LIMIT,
    offset: Annotated[
        int,
        Field(
            default=0,
            ge=0,
            description="Zero-based starting index for pagination (>= 0).",
        ),
    ] = 0,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Get all objects of a specific STIX type.

    This is a generic method to retrieve ATT&CK/CTI objects by STIX type.
    It complements more specific tools such as get_all_techniques(),
    get_all_groups(), etc.

    Common STIX types include:
      - 'attack-pattern'          (techniques)
      - 'malware'                 (malware)
      - 'tool'                    (tools)
      - 'intrusion-set'           (APT groups)
      - 'campaign'                (campaigns)
      - 'course-of-action'        (mitigations)
      - 'x-mitre-matrix'          (matrices)
      - 'x-mitre-tactic'          (tactics)
      - 'x-mitre-data-source'     (data sources)
      - 'x-mitre-data-component'  (data components)
      - 'x-mitre-asset'           (ICS assets)

    Args:
        stix_type: STIX object type to fetch.
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics', ...).
        remove_revoked_deprecated: Exclude revoked/deprecated objects.
        include_description: Include object descriptions in output.

    Returns:
        {
          "stix_type": "<type>",
          "domain": "<domain>",
          "count": int,
          "objects": [
            {
              "name": "...",
              "stix_id": "<stix-id>",
              "attack_id": "<T/G/S/M/C/... or null>",
              "description": "<text or null>",
            },
            ...
          ],
          "formatted": "<multi-line readable text>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)

    try:
        objs = attack_data.get_objects_by_type(
            stix_type,
            remove_revoked_deprecated=remove_revoked_deprecated,
        ) or []
    except Exception:
        objs = []

    safe_limit, safe_offset = _validate_pagination(limit, offset)

    if not objs:
        return {
            "stix_type": stix_type,
            "domain": domain,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "objects": [],
            "formatted": "",
            "message": (
                f"No objects of type '{stix_type}' found in domain '{domain}' "
                f"(remove_revoked_deprecated={remove_revoked_deprecated})."
            ),
        }

    objs.sort(
        key=lambda obj: (
            str(_stix_get(obj, "id") or ""),
            str(_stix_get(obj, "name") or ""),
        )
    )
    page_objs, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        objs, limit=limit, offset=offset
    )

    entries: list[dict[str, Any]] = []
    for obj in page_objs:
        stix_id = _stix_get(obj, "id")
        name = _stix_get(obj, "name")
        desc = _stix_get(obj, "description") if include_description else None

        try:
            attack_id = attack_data.get_attack_id(stix_id) if stix_id else None
        except Exception:
            attack_id = None

        entries.append(
            {
                "name": name,
                "stix_id": stix_id,
                "attack_id": attack_id,
                "description": desc,
            }
        )

    formatted = (
        format_objects(
            page_objs,
            include_description=include_description,
            domain=domain,
        )
        if include_formatted
        else ""
    )
    has_more = (safe_offset + len(entries)) < total_count

    return {
        "stix_type": stix_type,
        "domain": domain,
        "count": len(entries),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": safe_offset + len(entries) if has_more else None,
        "objects": entries,
        "formatted": formatted,
        "message": (
            f"Showing {len(entries)} of {total_count} object(s) of type '{stix_type}' "
            f"(offset={safe_offset}) in domain '{domain}' "
            f"(remove_revoked_deprecated={remove_revoked_deprecated})."
        ),
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_tactics_by_matrix(
    matrix_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = False,
    include_formatted: bool = True,
):
    """
    Get all ATT&CK tactics belonging to a specific matrix.

    Accepts either a STIX ID ("x-mitre-matrix--UUID") or an ATT&CK matrix ID/name
    (e.g., "enterprise-attack", "mobile-attack", "ics-attack", "Enterprise ATT&CK").

    Args:
        matrix_stix_id: STIX ID ("x-mitre-matrix--UUID") or ATT&CK matrix ID (e.g., "enterprise-attack").
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Whether to include tactic descriptions.
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
          "found": bool,
          "count": int,
          "tactics": [
            {
              "name": "...",
              "stix_id": "...",
              "description": "...",
              "attack_id": "TAxxxx" or null
            }
          ],
          "formatted": "<multiline string>",
          "message": "..."
        }
    """
    attack_data = get_attack_data(domain)

    resolved_id, matrix_obj, err = _resolve_stix_object(
        matrix_stix_id, domain=domain, expected_stix_type="x-mitre-matrix"
    )
    if resolved_id is None:
        return {
            "found": False,
            "count": 0,
            "tactics": [],
            "formatted": "",
            "message": err or f"Matrix '{matrix_stix_id}' not found in domain '{domain}'.",
        }
    matrix_stix_id = resolved_id
    matrix_name = _stix_get(matrix_obj, "name") if matrix_obj is not None else None

    try:
        tactics_map = attack_data.get_tactics_by_matrix() or {}
    except Exception:
        tactics_map = {}

    tactics = []
    if isinstance(tactics_map, dict):
        if matrix_name and matrix_name in tactics_map:
            tactics = tactics_map[matrix_name]
        elif matrix_stix_id in tactics_map:
            tactics = tactics_map[matrix_stix_id]
        elif matrix_name:
            for k, v in tactics_map.items():
                if k.lower() == matrix_name.lower():
                    tactics = v
                    break
        elif not matrix_stix_id and len(tactics_map) == 1:
            tactics = next(iter(tactics_map.values()))
    elif isinstance(tactics_map, list):
        tactics = tactics_map

    if not tactics:
        return {
            "found": False,
            "count": 0,
            "tactics": [],
            "formatted": "",
            "message": f"No tactics found for matrix '{matrix_stix_id}' in domain '{domain}'.",
        }

    results = []
    for tac in tactics:
        stix_id = _stix_get(tac, "id")
        try:
            attack_id = attack_data.get_attack_id(stix_id) if stix_id else None
        except Exception:
            attack_id = None

        results.append(
            {
                "name": _stix_get(tac, "name"),
                "stix_id": stix_id,
                "attack_id": attack_id,
                "description": _stix_get(tac, "description") if include_description else None,
            }
        )

    formatted = (
        format_objects(
            tactics,
            include_description=include_description,
            domain=domain,
        )
        if include_formatted
        else ""
    )

    return {
        "found": True,
        "count": len(results),
        "tactics": results,
        "formatted": formatted,
        "message": f"Found {len(results)} tactic(s) in matrix '{matrix_stix_id}'.",
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_tactics_by_technique(
    technique_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = False,
    include_formatted: bool = True,
):
    """
    Get all tactics associated with a specific ATT&CK technique.

    Techniques can belong to one or more tactics (kill chain phases).
    Accepts either a STIX ID ("attack-pattern--UUID") or an ATT&CK ID (e.g., "T1190").

    Args:
        technique_stix_id: Technique STIX UUID ("attack-pattern--UUID") or ATT&CK ID (e.g., "T1190").
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Whether to include tactic descriptions.
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
          "found": bool,
          "count": int,
          "tactics": [
            {
              "name": "...",
              "stix_id": "...",
              "attack_id": "TAxxxx" or null,
              "description": "...",
            }
          ],
          "formatted": "<multiline formatted output>",
          "message": "..."
        }
    """
    attack_data = get_attack_data(domain)

    resolved_id, _tech_obj, err = _resolve_stix_object(
        technique_stix_id, domain=domain, expected_stix_type="attack-pattern"
    )
    if resolved_id is None:
        return {
            "found": False,
            "count": 0,
            "tactics": [],
            "formatted": "",
            "message": err or f"Technique '{technique_stix_id}' not found in domain '{domain}'.",
        }
    technique_stix_id = resolved_id

    try:
        tactics = attack_data.get_tactics_by_technique(technique_stix_id) or []
    except Exception:
        tactics = []

    if not tactics:
        return {
            "found": False,
            "count": 0,
            "tactics": [],
            "formatted": "",
            "message": (
                f"No tactics found for technique '{technique_stix_id}' "
                f"in domain '{domain}'."
            ),
        }

    results = []
    for tac in tactics:
        stix_id = _stix_get(tac, "id")

        try:
            attack_id = attack_data.get_attack_id(stix_id) if stix_id else None
        except Exception:
            attack_id = None

        results.append(
            {
                "name": _stix_get(tac, "name"),
                "stix_id": stix_id,
                "attack_id": attack_id,
                "description": _stix_get(tac, "description")
                if include_description
                else None,
            }
        )

    formatted = (
        format_objects(
            tactics,
            include_description=include_description,
            domain=domain,
        )
        if include_formatted
        else ""
    )

    return {
        "found": True,
        "count": len(results),
        "tactics": results,
        "formatted": formatted,
        "message": f"Found {len(results)} tactic(s) associated with the technique.",
    }


@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_objects_created_after(
    timestamp: str,
    domain: str = "enterprise",
    include_description: bool = True,
    remove_revoked_deprecated: bool = True,
    stix_type: Optional[str] = None,
    limit: PageLimit = DEFAULT_PAGE_LIMIT,
    offset: PageOffset = 0,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Get all ATT&CK objects created after a specific timestamp.

    Useful for detecting new additions to the framework.
    Timestamp must be ISO8601 format, e.g., '2024-01-01T00:00:00Z'.

    Args:
        timestamp: ISO8601 timestamp string (e.g., '2025-01-01T00:00:00Z').
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Whether to include object descriptions.
        remove_revoked_deprecated: Whether to exclude revoked/deprecated objects.
        stix_type: Optional STIX type filter (e.g., 'attack-pattern', 'intrusion-set',
                   'malware', 'campaign', 'x-mitre-detection-strategy').
        limit: Maximum number of items to return per page (1-200).
        offset: Zero-based starting index for pagination (>= 0).
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
            "found": bool,
            "count": int,
            "total_count": int,
            "offset": int,
            "limit": int,
            "has_more": bool,
            "next_offset": int | None,
            "objects": [...],
            "formatted": "<pretty text>",
            "message": "..."
        }
    """
    attack_data = get_attack_data(domain)
    safe_limit, safe_offset = _validate_pagination(limit, offset)
    norm_stix_type = (stix_type or "").strip().lower() or None

    try:
        objects = attack_data.get_objects_created_after(
            timestamp, remove_revoked_deprecated=remove_revoked_deprecated
        ) or []
    except Exception as e:
        return {
            "found": False,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "objects": [],
            "formatted": "",
            "message": f"Error retrieving objects created after {timestamp}: {e}",
        }

    if norm_stix_type:
        objects = [
            item
            for item in objects
            if (_stix_get(_unwrap_stix_object(item), "type") or "").lower() == norm_stix_type
        ]

    if not objects:
        type_clause = f" of type '{norm_stix_type}'" if norm_stix_type else ""
        return {
            "found": False,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "objects": [],
            "formatted": "",
            "message": f"No objects{type_clause} created after '{timestamp}' in domain '{domain}'.",
        }

    objects.sort(
        key=lambda item: (
            str(_stix_get(_unwrap_stix_object(item), "created") or ""),
            str(_stix_get(_unwrap_stix_object(item), "id") or ""),
        )
    )
    page_objects, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        objects, limit=limit, offset=offset
    )

    results = []
    for item in page_objects:
        obj = _unwrap_stix_object(item)
        stix_id = _stix_get(obj, "id")
        attack_id = None
        try:
            if stix_id:
                attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            pass

        results.append(
            {
                "id": attack_id,
                "name": _stix_get(obj, "name"),
                "stix_id": stix_id,
                "type": _stix_get(obj, "type"),
                "description": _stix_get(obj, "description")
                if include_description
                else None,
            }
        )

    formatted = (
        format_objects(page_objects, include_description=include_description, domain=domain)
        if include_formatted
        else ""
    )
    has_more = (safe_offset + len(results)) < total_count
    type_clause = f" of type '{norm_stix_type}'" if norm_stix_type else ""

    return {
        "found": True,
        "count": len(results),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": safe_offset + len(results) if has_more else None,
        "objects": results,
        "formatted": formatted,
        "message": f"Showing {len(results)} of {total_count} objects{type_clause} created after {timestamp} (offset={safe_offset}).",
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_objects_modified_after(
    timestamp: str,
    domain: str = "enterprise",
    include_description: bool = True,
    remove_revoked_deprecated: bool = True,
    stix_type: Optional[str] = None,
    limit: PageLimit = DEFAULT_PAGE_LIMIT,
    offset: PageOffset = 0,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Get all ATT&CK objects modified after a specific timestamp.

    Useful for tracking updates and changes to the ATT&CK framework.
    Timestamp must be ISO8601 format, e.g., '2024-01-01T00:00:00Z'.

    Args:
        timestamp: ISO8601 timestamp string (e.g., '2025-01-01T00:00:00Z').
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Whether to include object descriptions.
        remove_revoked_deprecated: Whether to exclude revoked/deprecated objects.
        stix_type: Optional STIX type filter (e.g., 'attack-pattern', 'intrusion-set',
                   'malware', 'campaign', 'x-mitre-detection-strategy').
        limit: Maximum number of items to return per page (1-200).
        offset: Zero-based starting index for pagination (>= 0).
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
            "found": bool,
            "count": int,
            "total_count": int,
            "offset": int,
            "limit": int,
            "has_more": bool,
            "next_offset": int | None,
            "objects": [...],
            "formatted": "<pretty text>",
            "message": "..."
        }
    """
    attack_data = get_attack_data(domain)
    safe_limit, safe_offset = _validate_pagination(limit, offset)
    norm_stix_type = (stix_type or "").strip().lower() or None

    try:
        objects = attack_data.get_objects_modified_after(
            timestamp, remove_revoked_deprecated=remove_revoked_deprecated
        ) or []
    except Exception as e:
        return {
            "found": False,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "objects": [],
            "formatted": "",
            "message": f"Error retrieving objects modified after {timestamp}: {e}",
        }

    if norm_stix_type:
        objects = [
            item
            for item in objects
            if (_stix_get(_unwrap_stix_object(item), "type") or "").lower() == norm_stix_type
        ]

    if not objects:
        type_clause = f" of type '{norm_stix_type}'" if norm_stix_type else ""
        return {
            "found": False,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "objects": [],
            "formatted": "",
            "message": f"No objects{type_clause} modified after '{timestamp}' in domain '{domain}'.",
        }

    objects.sort(
        key=lambda item: (
            str(_stix_get(_unwrap_stix_object(item), "modified") or ""),
            str(_stix_get(_unwrap_stix_object(item), "id") or ""),
        )
    )
    page_objects, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        objects, limit=limit, offset=offset
    )

    results: list[Dict[str, Any]] = []
    for item in page_objects:
        obj = _unwrap_stix_object(item)
        stix_id = _stix_get(obj, "id")
        try:
            attack_id = attack_data.get_attack_id(stix_id) if stix_id else None
        except Exception:
            attack_id = None

        results.append(
            {
                "id": attack_id,
                "name": _stix_get(obj, "name"),
                "stix_id": stix_id,
                "type": _stix_get(obj, "type"),
                "description": _stix_get(obj, "description")
                if include_description
                else None,
            }
        )

    formatted = (
        format_objects(
            page_objects,
            include_description=include_description,
            domain=domain,
        )
        if include_formatted
        else ""
    )
    has_more = (safe_offset + len(results)) < total_count
    type_clause = f" of type '{norm_stix_type}'" if norm_stix_type else ""

    return {
        "found": True,
        "count": len(results),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": safe_offset + len(results) if has_more else None,
        "objects": results,
        "formatted": formatted,
        "message": f"Showing {len(results)} of {total_count} objects{type_clause} modified after {timestamp} (offset={safe_offset}).",
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_revoked_techniques(
    domain: str = "enterprise",
    include_description: bool = True,
    limit: PageLimit = DEFAULT_PAGE_LIMIT,
    offset: PageOffset = 0,
    include_formatted: bool = True,
) -> Dict[str, Any]:
    """
    Get all revoked techniques for a domain.

    Revoked techniques are no longer valid in the framework, often because
    they were merged or replaced.

    Args:
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Whether to include technique descriptions.
        limit: Maximum number of items to return per page (1-200).
        offset: Zero-based starting index for pagination (>= 0).
        include_formatted: If False, omits the human-readable formatted block to save tokens.

    Returns:
        {
            "found": bool,
            "count": int,
            "total_count": int,
            "offset": int,
            "limit": int,
            "has_more": bool,
            "next_offset": int | None,
            "techniques": [...],
            "formatted": "<pretty output>",
            "message": "..."
        }
    """
    attack_data = get_attack_data(domain)
    safe_limit, safe_offset = _validate_pagination(limit, offset)

    try:
        all_techniques = attack_data.get_techniques(remove_revoked_deprecated=False)
    except Exception as e:
        return {
            "found": False,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "techniques": [],
            "formatted": "",
            "message": f"Error retrieving techniques: {e}",
        }

    revoked = [t for t in all_techniques if _stix_get(t, "revoked", False)]

    if not revoked:
        return {
            "found": False,
            "count": 0,
            "total_count": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "has_more": False,
            "next_offset": None,
            "techniques": [],
            "formatted": "",
            "message": f"No revoked techniques found in domain '{domain}'.",
        }

    revoked_sorted = sorted(
        revoked,
        key=lambda t: (
            str(_stix_get(t, "name") or ""),
            str(_stix_get(t, "id") or ""),
        ),
    )
    page_revoked, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        revoked_sorted, limit=limit, offset=offset
    )

    output_items = []
    for tech in page_revoked:
        stix_id = _stix_get(tech, "id")
        try:
            attack_id = attack_data.get_attack_id(stix_id) if stix_id else None
        except Exception:
            attack_id = None

        output_items.append(
            {
                "id": attack_id,
                "name": _stix_get(tech, "name"),
                "stix_id": stix_id,
                "revoked": True,
                "description": _stix_get(tech, "description")
                if include_description
                else None,
            }
        )

    formatted = (
        format_objects(
            page_revoked,
            include_description=include_description,
            domain=domain,
        )
        if include_formatted
        else ""
    )

    return {
        "found": True,
        "count": len(output_items),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": next_offset,
        "techniques": output_items,
        "formatted": formatted,
        "message": f"Found {total_count} revoked techniques in '{domain}' (returning {len(output_items)} at offset {safe_offset}).",
    }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def generate_layer(
    attack_id: str = "",
    score: int = 1,
    domain: str = "enterprise",
    attack_ids: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Generate an ATT&CK Navigator layer for visualization with deterministic technique sorting.

    Produces a Navigator v4.5 JSON layer (pinned to the active ATT&CK dataset release, v20.1)
    highlighting active techniques associated with one or more ATT&CK IDs.

    Supported ATT&CK ID prefixes:
      - Gxxxx : groups (intrusion sets)
      - Mxxxx : mitigations (course-of-action)
      - Sxxxx : software (tool/malware)
      - Cxxxx : campaigns
      - DCxxxx : data components (ATT&CK v20.1; legacy Dxxxx also accepted)
      - Txxxx / Txxxx.xxx : techniques and sub-techniques

    Multiple IDs may be provided either as a comma-separated `attack_id` string
    (e.g., "T1190, T1059.001") or via the `attack_ids` list (e.g., ["T1190", "G0016"]).

    Args:
        attack_id: Single ATT&CK ID or comma-separated ATT&CK IDs (Gxxxx, Mxxxx, Sxxxx, Cxxxx, DCxxxx/Dxxxx, or Txxxx/Txxxx.xxx).
        score: Score to assign to all matched techniques in the layer.
        domain: ATT&CK domain ("enterprise", "mobile", or "ics").
        attack_ids: Optional list of ATT&CK IDs to combine into a single layer.

    Returns:
        {
          "success": bool,
          "attack_id": "<normalized ID or comma-separated IDs>",
          "attack_ids": ["<ID>", ...],
          "domain": "<domain>",
          "count": int,              # number of unique active techniques in layer
          "layer": { ... } | null,   # ATT&CK Navigator layer JSON (techniques sorted deterministically)
          "message": "<summary or error>"
        }
    """
    import re

    domain = (domain or "enterprise").strip().lower()

    # Collect and normalize one or more ATT&CK IDs (deduplicated, preserving order)
    raw_tokens: List[str] = []
    if isinstance(attack_id, str) and attack_id.strip():
        raw_tokens.extend(part.strip() for part in attack_id.split(","))
    if attack_ids is not None:
        for item in attack_ids:
            if isinstance(item, str):
                raw_tokens.extend(part.strip() for part in item.split(","))
            else:
                raw_tokens.append(str(item).strip())

    normalized_ids: List[str] = []
    seen_input_ids = set()
    for tok in raw_tokens:
        if not tok:
            continue
        up = tok.upper()
        if up not in seen_input_ids:
            seen_input_ids.add(up)
            normalized_ids.append(up)

    display_id = ", ".join(normalized_ids)

    if domain not in DOMAINS:
        return {
            "success": False,
            "attack_id": display_id,
            "attack_ids": normalized_ids,
            "domain": domain,
            "count": 0,
            "layer": None,
            "message": f"Invalid domain '{domain}'. Must be one of: {', '.join(DOMAINS)}.",
        }

    if not normalized_ids:
        return {
            "success": False,
            "attack_id": "",
            "attack_ids": [],
            "domain": domain,
            "count": 0,
            "layer": None,
            "message": (
                "No ATT&CK ID provided. Supply attack_id or attack_ids with valid "
                "GXXXX (group), MXXXX (mitigation), SXXXX (software), CXXXX (campaign), "
                "DCXXXX/DXXXX (data component), or TXXXX/TXXXX.XXX (technique) IDs."
            ),
        }

    # Validate ATT&CK ID formats: Gxxxx, Mxxxx, Sxxxx, Cxxxx, DCxxxx/Dxxxx, or Txxxx/Txxxx.xxx
    valid_id_re = re.compile(r"^(?:(?:[CGMSD]|DC)\d+|T\d+(?:\.\d+)?)$")
    invalid_ids = [aid for aid in normalized_ids if not valid_id_re.match(aid)]
    if invalid_ids:
        return {
            "success": False,
            "attack_id": display_id,
            "attack_ids": normalized_ids,
            "domain": domain,
            "count": 0,
            "layer": None,
            "message": (
                f"Invalid ATT&CK ID format: {', '.join(repr(x) for x in invalid_ids)}. Must be "
                "GXXXX (group), MXXXX (mitigation), SXXXX (software), CXXXX (campaign), "
                "DCXXXX/DXXXX (data component), or TXXXX/TXXXX.XXX (technique)."
            ),
        }

    stix_path = get_stix_path(domain)
    if not stix_path.exists():
        return {
            "success": False,
            "attack_id": display_id,
            "attack_ids": normalized_ids,
            "domain": domain,
            "count": 0,
            "layer": None,
            "message": f"STIX data for domain '{domain}' is not available.",
        }

    # Generate Navigator layer directly from loaded MitreAttackData for complete v20.1 accuracy
    try:
        ad = get_attack_data(domain)
        tech_map: Dict[str, Dict[str, Any]] = {}
        tech_comments: Dict[str, List[str]] = {}
        resolved_sources: List[Tuple[str, str]] = []
        missing_ids: List[str] = []

        for aid in normalized_ids:
            src_obj = None
            raw_items: List[Any] = []
            relation_label = "Associated with"

            if aid.startswith("T"):
                src_obj = ad.get_object_by_attack_id(aid, "attack-pattern")
                if src_obj is not None:
                    raw_items = [src_obj]
                    relation_label = "Technique"
            elif aid.startswith("G"):
                src_obj = ad.get_object_by_attack_id(aid, "intrusion-set")
                if src_obj is not None:
                    raw_items = ad.get_techniques_used_by_group(_stix_get(src_obj, "id")) or []
                    relation_label = "Used by group"
            elif aid.startswith("M"):
                src_obj = ad.get_object_by_attack_id(aid, "course-of-action")
                if src_obj is not None:
                    raw_items = ad.get_techniques_mitigated_by_mitigation(_stix_get(src_obj, "id")) or []
                    relation_label = "Mitigated by"
            elif aid.startswith("S"):
                src_obj = ad.get_object_by_attack_id(aid, "malware") or ad.get_object_by_attack_id(aid, "tool")
                if src_obj is not None:
                    raw_items = ad.get_techniques_used_by_software(_stix_get(src_obj, "id")) or []
                    relation_label = "Used by software"
            elif aid.startswith("C"):
                src_obj = ad.get_object_by_attack_id(aid, "campaign")
                if src_obj is not None:
                    raw_items = ad.get_techniques_used_by_campaign(_stix_get(src_obj, "id")) or []
                    relation_label = "Used by campaign"
            elif aid.startswith("DC") or aid.startswith("D"):
                src_obj = ad.get_object_by_attack_id(aid, "x-mitre-data-component")
                if src_obj is not None:
                    dc_stix_id = _stix_get(src_obj, "id")
                    v20_idx = _get_v20_detection_index(domain)
                    for tid in v20_idx["dc_to_techs"].get(dc_stix_id, []):
                        tobj = ad.get_object_by_stix_id(tid)
                        if tobj is not None:
                            raw_items.append(tobj)
                    if not raw_items:
                        raw_items = ad.get_techniques_detected_by_datacomponent(dc_stix_id) or []
                    relation_label = "Detected via data component"

            if src_obj is None:
                missing_ids.append(aid)
                continue

            src_name = _stix_get(src_obj, "name") or aid
            resolved_sources.append((aid, src_name))

            for item in raw_items:
                tobj = _unwrap_stix_object(item)
                if tobj is None or _stix_get(tobj, "revoked", False) or _stix_get(tobj, "x_mitre_deprecated", False):
                    continue
                tid = _stix_get(tobj, "id")
                t_aid = ad.get_attack_id(tid) if tid else None
                if not t_aid:
                    continue

                if aid.startswith("T"):
                    comment = f"Technique: {src_name} ({t_aid})"
                else:
                    comment = f"{relation_label} {src_name} ({aid})"
                    if isinstance(item, dict) and item.get("relationships"):
                        r_desc = _stix_get(item["relationships"][0], "description")
                        if isinstance(r_desc, str) and r_desc.strip():
                            clean_desc = " ".join(r_desc.strip().split())
                            comment = clean_desc[:197] + "..." if len(clean_desc) > 200 else clean_desc

                comments_list = tech_comments.setdefault(t_aid, [])
                if comment not in comments_list:
                    comments_list.append(comment)

                if t_aid not in tech_map:
                    tech_map[t_aid] = {
                        "techniqueID": t_aid,
                        "score": score,
                        "comment": comment,
                        "enabled": True,
                    }

        if missing_ids:
            if len(missing_ids) == 1 and len(normalized_ids) == 1:
                missing_msg = f"ATT&CK object '{missing_ids[0]}' was not found in domain '{domain}'."
            else:
                missing_msg = (
                    f"ATT&CK object(s) not found in domain '{domain}': "
                    f"{', '.join(missing_ids)}."
                )
            return {
                "success": False,
                "attack_id": display_id,
                "attack_ids": normalized_ids,
                "domain": domain,
                "count": 0,
                "layer": None,
                "message": missing_msg,
            }

        tech_entries: List[Dict[str, Any]] = []
        for t_aid in sorted(tech_map.keys(), key=lambda tid: _attack_id_sort_key(tid, "", "")):
            entry = tech_map[t_aid]
            joined_comment = " | ".join(tech_comments[t_aid])
            entry["comment"] = joined_comment[:197] + "..." if len(joined_comment) > 200 else joined_comment
            tech_entries.append(entry)

        if not tech_entries:
            if len(resolved_sources) == 1:
                only_id, only_name = resolved_sources[0]
                empty_msg = f"No active techniques found for '{only_id}' ({only_name}) in domain '{domain}'."
            else:
                empty_msg = f"No active techniques found for '{display_id}' in domain '{domain}'."
            return {
                "success": False,
                "attack_id": display_id,
                "attack_ids": normalized_ids,
                "domain": domain,
                "count": 0,
                "layer": None,
                "message": empty_msg,
            }

        if len(resolved_sources) == 1:
            only_id, only_name = resolved_sources[0]
            layer_name = f"{only_name} ({only_id})"
            layer_desc = (
                f"ATT&CK Navigator layer for {only_name} ({only_id}) "
                f"in {domain} v{release_info.LATEST_VERSION}."
            )
        else:
            preview = ", ".join(normalized_ids[:5])
            if len(normalized_ids) > 5:
                preview += f", +{len(normalized_ids) - 5} more"
            layer_name = f"Combined ATT&CK Layer ({preview})"
            layer_desc = (
                f"ATT&CK Navigator layer for {len(normalized_ids)} ATT&CK IDs "
                f"({display_id}) in {domain} v{release_info.LATEST_VERSION}."
            )

        layer_dict = {
            "name": layer_name,
            "versions": {
                "attack": str(release_info.LATEST_VERSION),
                "navigator": "5.1.0",
                "layer": "4.5",
            },
            "domain": f"{domain}-attack",
            "description": layer_desc,
            "layout": {
                "layout": "side",
                "aggregateFunction": "average",
                "expandedSubtechniques": "none",
            },
            "gradient": {
                "colors": ["#ffffff", "#66b1ff"],
                "minValue": 0,
                "maxValue": max(score, 1),
            },
            "techniques": tech_entries,
        }
        count = len(tech_entries)

        return {
            "success": True,
            "attack_id": display_id,
            "attack_ids": normalized_ids,
            "domain": domain,
            "count": count,
            "layer": layer_dict,
            "message": (
                f"Generated Navigator layer for '{display_id}' in domain "
                f"'{domain}' with {count} technique(s)."
            ),
        }

    except Exception as e:
        return {
            "success": False,
            "attack_id": display_id,
            "attack_ids": normalized_ids,
            "domain": domain,
            "count": 0,
            "layer": None,
            "message": f"Failed to generate layer: {e}",
        }

@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_layer_metadata(domain: str = "enterprise") -> Dict[str, Any]:
    """
    Return a standard ATT&CK Navigator layer metadata template.

    This provides default layer properties (version info, gradient settings,
    layout, filters, etc.) adapted to a specific ATT&CK domain.

    Useful for clients that want to build custom layers programmatically
    without starting from scratch.

    Args:
        domain: One of "enterprise", "mobile", "ics". Defaults to "enterprise".

    Returns:
        {
          "success": bool,
          "domain": "<domain>",
          "metadata": { ... },  # Navigator layer metadata
          "message": "<summary>"
        }
    """
    # Base Navigator layer template
    base_metadata = {
        "name": "layer",
        "versions": {"attack": str(release_info.LATEST_VERSION), "navigator": "5.1.0", "layer": "4.5"},
        "description": "",
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "expandedSubtechniques": "none",
        },
        "techniques": [],
        "gradient": {
            "colors": ["#ff6666ff", "#ffe766ff", "#8ec843ff"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [],
        "metadata": [],
        "links": [],
        "tacticRowBackground": "#dddddd",
    }

    # Domain → platform filter mappings (aligned with ATT&CK v20.1 STIX x_mitre_platforms)
    domain_configs = {
        "enterprise": {
            "domain": "enterprise-attack",
            "filters": {
                "platforms": [
                    "Windows", "Linux", "macOS", "Network Devices", "ESXi", "PRE",
                    "Containers", "IaaS", "SaaS", "Office Suite",
                    "Identity Provider"
                ]
            },
        },
        "mobile": {
            "domain": "mobile-attack",
            "filters": {"platforms": ["Android", "iOS"]},
        },
        "ics": {
            "domain": "ics-attack",
            "filters": {"platforms": ["Embedded", "Linux", "Network Devices", "None", "Windows"]},
        },
    }

    # Normalize domain
    domain = (domain or "enterprise").strip().lower()
    if domain not in domain_configs:
        return {
            "success": False,
            "domain": domain,
            "metadata": None,
            "message": (
                "Invalid domain. Must be one of: enterprise, mobile, ics."
            ),
        }

    # Merge templates
    metadata = base_metadata.copy()
    metadata.update(domain_configs[domain])

    return {
        "success": True,
        "domain": domain,
        "metadata": metadata,
        "message": f"Returned Navigator layer metadata for {domain} domain.",
    }



def _normalize_detection_platforms(
    platforms: Optional[List[str]],
    an_by_id: Optional[Dict[str, Any]] = None,
) -> Optional[List[str]]:
    """Normalize an optional list of platform filter names for detection strategies.

    Returns None when no non-empty platform filter is requested (preserving
    unfiltered backward-compatible behavior). When provided, resolves canonical
    platform casing from known analytics in the domain when available and
    returns a deduplicated, deterministically sorted list.
    """
    if platforms is None:
        return None
    raw_items = [str(p).strip() for p in platforms if p is not None and str(p).strip()]
    if not raw_items:
        return None

    known_lower: Dict[str, str] = {}
    if an_by_id:
        for an_obj in an_by_id.values():
            for p in (_stix_get(an_obj, "x_mitre_platforms") or []):
                if p and str(p).strip():
                    ps = str(p).strip()
                    known_lower[ps.lower()] = ps

    dedup: Dict[str, str] = {}
    for item in raw_items:
        key = item.lower()
        if key not in dedup:
            dedup[key] = known_lower.get(key, item)
    return sorted(dedup.values())


def _build_detection_batch_metadata(
    domain: str,
    include_description: bool,
    exists: Optional[bool] = None,
    detail_level: str = "compact",
    include_log_sources: bool = False,
    applied_platforms: Optional[List[str]] = None,
    suggested_platforms: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Build version, source provenance, and coverage caveat metadata for batch detection responses."""
    if domain in DOMAINS:
        prov = _build_domain_provenance(domain, exists=exists)
    else:
        prov = {
            "loaded_version": None,
            "stix_spec_version": "2.1",
            "source_url": None,
            "source_repository": _SOURCE_REPOSITORY_URL,
            "source_release_date": None,
            "freshness_status": "invalid_domain",
        }
    meta: Dict[str, Any] = {
        "attack_version": prov.get("loaded_version") or str(release_info.LATEST_VERSION),
        "domain": domain,
        "source_url": prov.get("source_url"),
        "source_release_date": prov.get("source_release_date"),
        "freshness_status": prov.get("freshness_status"),
        "detail_level": detail_level,
        "max_batch_size": MAX_BATCH_DETECTION_TECHNIQUES,
        "caveat": _DETECTION_COVERAGE_CAVEAT,
    }
    if applied_platforms is not None:
        meta["applied_platforms"] = applied_platforms
    if suggested_platforms:
        meta["suggested_platforms"] = suggested_platforms
    if detail_level == "full":
        meta["stix_spec_version"] = prov.get("stix_spec_version", "2.1")
        meta["source_repository"] = prov.get("source_repository", _SOURCE_REPOSITORY_URL)
        meta["include_description"] = bool(include_description)
        meta["include_log_sources"] = True
    elif include_log_sources or include_description:
        meta["include_description"] = bool(include_description)
        meta["include_log_sources"] = bool(include_log_sources)
    return meta


def _empty_batch_coverage(detail_level: str = "compact") -> Dict[str, Any]:
    if detail_level == "compact":
        return {
            "detection_strategies": {},
            "analytics": {},
            "data_components": {},
            "edges": {
                "technique_to_detection_strategy": {},
                "detection_strategy_to_analytic": {},
                "analytic_to_data_component": {},
            },
        }
    return {
        "detection_strategies": [],
        "analytics": [],
        "data_components": [],
        "edges": {
            "technique_to_detection_strategy": [],
            "detection_strategy_to_analytic": [],
            "analytic_to_data_component": [],
        },
    }


def _get_detection_strategies_batch(
    technique_stix_id: str,
    technique_ids: Optional[List[str]],
    domain: str,
    include_description: bool,
    detail_level: str = "compact",
    include_log_sources: bool = False,
    platforms: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Deterministic, deduplicated batch detection-strategy lookup for multiple techniques."""
    dom = (domain or "enterprise").strip().lower()
    level = (detail_level or "compact").strip().lower() if isinstance(detail_level, str) else str(detail_level).lower()
    eff_log_sources = bool(include_log_sources) or (level == "full")
    raw_applied_platforms = _normalize_detection_platforms(platforms)

    raw_tokens: List[str] = []
    if isinstance(technique_stix_id, str) and technique_stix_id.strip():
        raw_tokens.extend(part.strip() for part in technique_stix_id.split(","))
    if technique_ids is not None:
        for item in technique_ids:
            if isinstance(item, str):
                raw_tokens.extend(part.strip() for part in item.split(","))
            elif item is not None:
                raw_tokens.append(str(item).strip())

    non_empty_tokens = [tok for tok in raw_tokens if tok]
    requested_count = len(non_empty_tokens)

    unique_tokens: List[str] = []
    seen_tokens: set[str] = set()
    dup_tokens: set[str] = set()
    duplicates_removed_count = 0
    for tok in non_empty_tokens:
        canon = tok.lower() if "--" in tok else tok.upper()
        if canon in seen_tokens:
            dup_tokens.add(canon)
            duplicates_removed_count += 1
        else:
            seen_tokens.add(canon)
            unique_tokens.append(canon)

    def _error_response(
        error_code: str,
        message: str,
        techniques_list: Optional[List[Dict[str, Any]]] = None,
        exists: Optional[bool] = None,
    ) -> Dict[str, Any]:
        eff_level = level if level in _VALID_BATCH_DETAIL_LEVELS else "compact"
        tech_rows = techniques_list or []
        unavail_count = sum(1 for t in tech_rows if t.get("status") == "UNAVAILABLE")
        return {
            "found": False,
            "batch": True,
            "detail_level": eff_level,
            "domain": dom,
            "error_code": error_code,
            "count": 0,
            "counts": {
                "requested_inputs": requested_count,
                "unique_inputs": len(unique_tokens),
                "duplicates_removed": duplicates_removed_count,
                "techniques_total": len(tech_rows),
                "found": 0,
                "valid_no_detection": 0,
                "not_found": 0,
                "invalid": 0,
                "unavailable": unavail_count,
                "detection_strategies": 0,
                "analytics": 0,
                "data_components": 0,
            },
            "duplicates_removed": sorted(dup_tokens),
            "techniques": tech_rows,
            "coverage": _empty_batch_coverage(eff_level),
            "metadata": _build_detection_batch_metadata(
                dom,
                include_description=include_description,
                exists=exists,
                detail_level=eff_level,
                include_log_sources=eff_log_sources,
                applied_platforms=raw_applied_platforms,
            ),
            "message": message,
        }

    if level not in _VALID_BATCH_DETAIL_LEVELS:
        return _error_response(
            "INVALID_DETAIL_LEVEL",
            f"Invalid detail_level '{detail_level}'. Must be one of: {', '.join(_VALID_BATCH_DETAIL_LEVELS)}.",
        )

    if dom not in DOMAINS:
        return _error_response(
            "INVALID_DOMAIN",
            f"Invalid domain '{dom}'. Must be one of: {', '.join(DOMAINS)}.",
        )

    if not unique_tokens:
        return _error_response(
            "EMPTY_INPUT",
            (
                "No technique IDs provided. Supply one or more ATT&CK technique IDs "
                "(e.g., 'T1190,T1059.001') or STIX IDs ('attack-pattern--<uuid>')."
            ),
        )

    if len(unique_tokens) > MAX_BATCH_DETECTION_TECHNIQUES:
        return _error_response(
            "BATCH_LIMIT_EXCEEDED",
            (
                f"Batch size {len(unique_tokens)} exceeds maximum allowed "
                f"{MAX_BATCH_DETECTION_TECHNIQUES} unique technique IDs per call."
            ),
        )

    stix_path = get_stix_path(dom)
    if not stix_path.exists():
        unavailable_rows = [
            {
                "input": tok,
                "matched_inputs": [tok],
                "status": "UNAVAILABLE",
                "attack_id": None,
                "name": None,
                "stix_id": None,
                "revoked": False,
                "deprecated": False,
                "detection_strategy_ids": [],
                "analytic_ids": [],
                "data_component_ids": [],
                "platforms": [],
                "log_sources": [],
                "error": f"STIX data for domain '{dom}' is not available.",
            }
            for tok in sorted(unique_tokens)
        ]
        return _error_response(
            "DOMAIN_UNAVAILABLE",
            f"STIX data for domain '{dom}' is not available.",
            techniques_list=unavailable_rows,
            exists=False,
        )

    try:
        ad = get_attack_data(dom)
        v20_idx = _get_v20_detection_index(dom)
    except Exception as e:
        unavailable_rows = [
            {
                "input": tok,
                "matched_inputs": [tok],
                "status": "UNAVAILABLE",
                "attack_id": None,
                "name": None,
                "stix_id": None,
                "revoked": False,
                "deprecated": False,
                "detection_strategy_ids": [],
                "analytic_ids": [],
                "data_component_ids": [],
                "platforms": [],
                "log_sources": [],
                "error": f"Failed to load detection data for domain '{dom}': {e}",
            }
            for tok in sorted(unique_tokens)
        ]
        return _error_response(
            "DOMAIN_UNAVAILABLE",
            f"Failed to load detection data for domain '{dom}': {e}",
            techniques_list=unavailable_rows,
            exists=False,
        )

    tech_by_stix_id = v20_idx.get("tech_by_stix_id", {})
    tech_by_attack_id = v20_idx.get("tech_by_attack_id", {})
    tech_aid_map = v20_idx.get("tech_attack_id_by_id", {})
    ds_by_id = v20_idx["ds_by_id"]
    an_by_id = v20_idx["an_by_id"]
    dc_by_id = v20_idx["dc_by_id"]
    ds_aid_map = v20_idx.get("ds_attack_id_by_id", {})
    an_aid_map = v20_idx.get("an_attack_id_by_id", {})
    dc_aid_map = v20_idx.get("dc_attack_id_by_id", {})
    tech_to_ds = v20_idx["tech_to_ds"]
    an_to_dcs = v20_idx["an_to_dcs"]
    an_log_source_refs = v20_idx.get("an_log_source_refs", {})

    applied_platforms = _normalize_detection_platforms(platforms, an_by_id)
    platform_filter_lower = (
        {p.lower() for p in applied_platforms} if applied_platforms is not None else None
    )

    def _lookup_aid(cache_map: Dict[str, Optional[str]], stix_id: str) -> str:
        aid = cache_map.get(stix_id)
        if aid:
            return str(aid)
        try:
            resolved = ad.get_attack_id(stix_id)
            if resolved:
                return str(resolved)
        except Exception:
            pass
        return stix_id

    resolved_by_stix: Dict[str, Dict[str, Any]] = {}
    unresolved_rows: List[Dict[str, Any]] = []

    ds_cov: Dict[str, Dict[str, Any]] = {}
    an_cov: Dict[str, Dict[str, Any]] = {}
    dc_cov: Dict[str, Dict[str, Any]] = {}
    edges_t_ds: set[Tuple[str, str]] = set()
    edges_ds_an: set[Tuple[str, str]] = set()
    edges_an_dc: set[Tuple[str, str]] = set()

    for tok in unique_tokens:
        is_valid_syntax = bool(
            _TECHNIQUE_ATTACK_ID_RE.match(tok) or _TECHNIQUE_STIX_ID_RE.match(tok)
        )
        if not is_valid_syntax:
            unresolved_rows.append({
                "input": tok,
                "matched_inputs": [tok],
                "status": "INVALID",
                "attack_id": None,
                "name": None,
                "stix_id": None,
                "revoked": False,
                "deprecated": False,
                "detection_strategy_ids": [],
                "analytic_ids": [],
                "data_component_ids": [],
                "platforms": [],
                "log_sources": [],
                "error": (
                    f"Malformed or non-technique identifier '{tok}'. "
                    "Expected Txxxx, Txxxx.xxx, or attack-pattern--<uuid>."
                ),
            })
            continue

        tech_obj = None
        resolved_id = None
        if "--" in tok:
            tech_obj = tech_by_stix_id.get(tok.lower())
        else:
            tech_obj = tech_by_attack_id.get(tok.upper())
        if tech_obj is not None:
            resolved_id = _stix_get(tech_obj, "id")
            err = None
        else:
            err = f"Technique '{tok}' not found in domain '{dom}'."
        if resolved_id is None:
            unresolved_rows.append({
                "input": tok,
                "matched_inputs": [tok],
                "status": "NOT_FOUND",
                "attack_id": tok if _TECHNIQUE_ATTACK_ID_RE.match(tok) else None,
                "name": None,
                "stix_id": tok if _TECHNIQUE_STIX_ID_RE.match(tok) else None,
                "revoked": False,
                "deprecated": False,
                "detection_strategy_ids": [],
                "analytic_ids": [],
                "data_component_ids": [],
                "platforms": [],
                "log_sources": [],
                "error": err,
            })
            continue

        if resolved_id in resolved_by_stix:
            existing = resolved_by_stix[resolved_id]
            if tok not in existing["matched_inputs"]:
                existing["matched_inputs"].append(tok)
                existing["matched_inputs"].sort()
                existing["input"] = existing["matched_inputs"][0]
            dup_tokens.add(tok)
            duplicates_removed_count += 1
            continue

        tech_aid = tech_aid_map.get(resolved_id)
        if tech_aid is None:
            try:
                tech_aid = ad.get_attack_id(resolved_id)
            except Exception:
                tech_aid = None
        tech_key = str(tech_aid or resolved_id)
        tech_name = _stix_get(tech_obj, "name")
        is_revoked = bool(_stix_get(tech_obj, "revoked", False))
        is_deprecated = bool(_stix_get(tech_obj, "x_mitre_deprecated", False))

        t_ds_ids: set[str] = set()
        t_an_ids: set[str] = set()
        t_dc_ids: set[str] = set()
        t_platforms: set[str] = set()
        t_log_sources: set[str] = set()

        for ds_stix_id in tech_to_ds.get(resolved_id, []):
            ds_obj = ds_by_id.get(ds_stix_id)
            if ds_obj is None:
                continue

            matching_analytics: List[Tuple[str, Any, List[str]]] = []
            for an_stix_id in (_stix_get(ds_obj, "x_mitre_analytic_refs") or []):
                an_obj = an_by_id.get(an_stix_id)
                if an_obj is None:
                    continue
                an_platforms = sorted(
                    {
                        str(p).strip()
                        for p in (_stix_get(an_obj, "x_mitre_platforms") or [])
                        if p and str(p).strip()
                    }
                )
                if platform_filter_lower is not None and not any(
                    p.lower() in platform_filter_lower for p in an_platforms
                ):
                    continue
                matching_analytics.append((an_stix_id, an_obj, an_platforms))

            if platform_filter_lower is not None and not matching_analytics:
                continue

            ds_aid = _lookup_aid(ds_aid_map, ds_stix_id)
            t_ds_ids.add(ds_aid)
            edges_t_ds.add((tech_key, ds_aid))

            ds_entry = ds_cov.get(ds_stix_id)
            if ds_entry is None:
                ds_entry = {
                    "attack_id": ds_aid,
                    "name": _stix_get(ds_obj, "name"),
                    "stix_id": ds_stix_id,
                    "_technique_ids": set(),
                    "_analytic_ids": set(),
                }
                if include_description:
                    ds_entry["description"] = _stix_get(ds_obj, "description")
                ds_cov[ds_stix_id] = ds_entry
            ds_entry["_technique_ids"].add(tech_key)

            for an_stix_id, an_obj, an_platforms in matching_analytics:
                an_aid = _lookup_aid(an_aid_map, an_stix_id)
                t_an_ids.add(an_aid)
                ds_entry["_analytic_ids"].add(an_aid)
                edges_ds_an.add((ds_aid, an_aid))
                t_platforms.update(an_platforms)

                an_entry = an_cov.get(an_stix_id)
                if an_entry is None:
                    an_dc_ids: List[str] = []
                    an_dc_seen: set[str] = set()
                    for dc_stix_id in an_to_dcs.get(an_stix_id, []):
                        dc_obj = dc_by_id.get(dc_stix_id)
                        dc_aid = _lookup_aid(dc_aid_map, dc_stix_id)
                        if dc_aid not in an_dc_seen:
                            an_dc_seen.add(dc_aid)
                            an_dc_ids.append(dc_aid)
                        if dc_stix_id not in dc_cov:
                            dc_cov[dc_stix_id] = {
                                "attack_id": dc_aid,
                                "name": _stix_get(dc_obj, "name") if dc_obj is not None else None,
                                "stix_id": dc_stix_id,
                                "_log_sources": set(),
                            }
                    an_dc_ids.sort(key=lambda x: _attack_id_sort_key(x, "", ""))

                    an_log_source_names: set[str] = set()
                    an_log_source_details: List[Dict[str, str]] = []
                    seen_ls: set[Tuple[str, str, str]] = set()
                    for lr in an_log_source_refs.get(an_stix_id, []):
                        lr_dc_stix = lr.get("data_component_stix_id")
                        lr_dc_aid = (
                            _lookup_aid(dc_aid_map, lr_dc_stix) if lr_dc_stix else ""
                        )
                        lr_name = lr.get("name") or ""
                        lr_channel = lr.get("channel") or ""
                        if lr_name:
                            an_log_source_names.add(lr_name)
                            if lr_dc_stix and lr_dc_stix in dc_cov:
                                dc_cov[lr_dc_stix]["_log_sources"].add(lr_name)
                        if include_description:
                            ls_key = (lr_dc_aid, lr_name, lr_channel)
                            if ls_key in seen_ls:
                                continue
                            seen_ls.add(ls_key)
                            ls_item: Dict[str, str] = {}
                            if lr_dc_aid:
                                ls_item["data_component_id"] = lr_dc_aid
                            if lr_name:
                                ls_item["name"] = lr_name
                            if lr_channel:
                                ls_item["channel"] = lr_channel
                            if ls_item:
                                an_log_source_details.append(ls_item)

                    an_entry = {
                        "attack_id": an_aid,
                        "name": _stix_get(an_obj, "name"),
                        "stix_id": an_stix_id,
                        "platforms": an_platforms,
                        "data_component_ids": an_dc_ids,
                        "log_sources": sorted(an_log_source_names),
                    }
                    if include_description:
                        an_log_source_details.sort(
                            key=lambda x: (
                                x.get("data_component_id", ""),
                                x.get("name", ""),
                                x.get("channel", ""),
                            )
                        )
                        an_entry["log_source_references"] = an_log_source_details
                        an_entry["description"] = _stix_get(an_obj, "description")
                    an_cov[an_stix_id] = an_entry

                for dc_aid in an_entry["data_component_ids"]:
                    t_dc_ids.add(dc_aid)
                    edges_an_dc.add((an_aid, dc_aid))
                t_log_sources.update(an_entry["log_sources"])

        status = "FOUND" if t_ds_ids else "VALID_NO_DETECTION"
        resolved_by_stix[resolved_id] = {
            "input": tok,
            "matched_inputs": [tok],
            "status": status,
            "attack_id": tech_aid,
            "name": tech_name,
            "stix_id": resolved_id,
            "revoked": is_revoked,
            "deprecated": is_deprecated,
            "detection_strategy_ids": sorted(
                t_ds_ids, key=lambda x: _attack_id_sort_key(x, "", "")
            ),
            "analytic_ids": sorted(
                t_an_ids, key=lambda x: _attack_id_sort_key(x, "", "")
            ),
            "data_component_ids": sorted(
                t_dc_ids, key=lambda x: _attack_id_sort_key(x, "", "")
            ),
            "platforms": sorted(t_platforms),
            "log_sources": sorted(t_log_sources),
            "error": None,
        }

    # Finalize deterministic ordering
    resolved_rows = sorted(
        resolved_by_stix.values(),
        key=lambda r: _attack_id_sort_key(r["attack_id"], r["name"], r["stix_id"]),
    )
    status_rank = {"NOT_FOUND": 1, "INVALID": 2, "UNAVAILABLE": 3}
    unresolved_rows.sort(
        key=lambda r: (status_rank.get(r["status"], 9), str(r["input"]))
    )
    techniques_out = resolved_rows + unresolved_rows

    ds_out: List[Dict[str, Any]] = []
    for entry in sorted(
        ds_cov.values(),
        key=lambda x: _attack_id_sort_key(x["attack_id"], x["name"], x["stix_id"]),
    ):
        item: Dict[str, Any] = {
            "attack_id": entry["attack_id"],
            "name": entry["name"],
            "stix_id": entry["stix_id"],
            "technique_ids": sorted(
                entry["_technique_ids"], key=lambda x: _attack_id_sort_key(x, "", "")
            ),
            "analytic_ids": sorted(
                entry["_analytic_ids"], key=lambda x: _attack_id_sort_key(x, "", "")
            ),
        }
        if include_description:
            item["description"] = entry.get("description")
        ds_out.append(item)

    an_out = sorted(
        an_cov.values(),
        key=lambda x: _attack_id_sort_key(x["attack_id"], x["name"], x["stix_id"]),
    )
    dc_out: List[Dict[str, Any]] = []
    for entry in sorted(
        dc_cov.values(),
        key=lambda x: _attack_id_sort_key(x["attack_id"], x["name"], x["stix_id"]),
    ):
        dc_out.append({
            "attack_id": entry["attack_id"],
            "name": entry["name"],
            "stix_id": entry["stix_id"],
            "log_sources": sorted(entry["_log_sources"]),
        })

    edges_out = {
        "technique_to_detection_strategy": [
            [t_id, ds_id]
            for t_id, ds_id in sorted(
                edges_t_ds,
                key=lambda p: (
                    _attack_id_sort_key(p[0], "", ""),
                    _attack_id_sort_key(p[1], "", ""),
                ),
            )
        ],
        "detection_strategy_to_analytic": [
            [ds_id, an_id]
            for ds_id, an_id in sorted(
                edges_ds_an,
                key=lambda p: (
                    _attack_id_sort_key(p[0], "", ""),
                    _attack_id_sort_key(p[1], "", ""),
                ),
            )
        ],
        "analytic_to_data_component": [
            [an_id, dc_id]
            for an_id, dc_id in sorted(
                edges_an_dc,
                key=lambda p: (
                    _attack_id_sort_key(p[0], "", ""),
                    _attack_id_sort_key(p[1], "", ""),
                ),
            )
        ],
    }

    found_count = sum(1 for r in techniques_out if r["status"] == "FOUND")
    no_det_count = sum(1 for r in techniques_out if r["status"] == "VALID_NO_DETECTION")
    not_found_count = sum(1 for r in techniques_out if r["status"] == "NOT_FOUND")
    invalid_count = sum(1 for r in techniques_out if r["status"] == "INVALID")
    unavail_count = sum(1 for r in techniques_out if r["status"] == "UNAVAILABLE")

    any_resolved = (found_count + no_det_count) > 0

    batch_suggested_platforms: List[str] = []
    if applied_platforms is not None and len(an_out) == 0:
        available_an_platforms = _extract_available_platforms(list(an_by_id.values()))
        batch_suggested_platforms = _suggest_attack_platforms_for_list(
            applied_platforms, available_an_platforms
        )
    batch_hint_clause = (
        f" Suggested ATT&CK platform(s): {', '.join(batch_suggested_platforms)}."
        if batch_suggested_platforms
        else ""
    )

    if level == "compact":
        compact_techniques: List[Dict[str, Any]] = []
        for r in techniques_out:
            if r["status"] in ("FOUND", "VALID_NO_DETECTION"):
                ct: Dict[str, Any] = {
                    "attack_id": r["attack_id"] or r["stix_id"],
                    "name": r["name"],
                    "status": r["status"],
                }
                if r["revoked"]:
                    ct["revoked"] = True
                if r["deprecated"]:
                    ct["deprecated"] = True
                if len(r["matched_inputs"]) > 1:
                    ct["matched_inputs"] = r["matched_inputs"]
                compact_techniques.append(ct)
            else:
                compact_techniques.append({
                    "input": r["input"],
                    "status": r["status"],
                    "error": r["error"],
                })

        compact_ds: Dict[str, Any] = {}
        for item in ds_out:
            if include_description:
                compact_ds[item["attack_id"]] = {
                    "name": item["name"],
                    "description": item.get("description"),
                }
            else:
                compact_ds[item["attack_id"]] = item["name"]

        compact_an: Dict[str, Any] = {}
        for item in an_out:
            an_val: Dict[str, Any] = {
                "name": item["name"],
                "platforms": item["platforms"],
            }
            if eff_log_sources:
                an_val["log_sources"] = item["log_sources"]
            if include_description:
                an_val["description"] = item.get("description")
            compact_an[item["attack_id"]] = an_val

        compact_dc: Dict[str, Any] = {}
        for item in dc_out:
            if eff_log_sources:
                compact_dc[item["attack_id"]] = {
                    "name": item["name"],
                    "log_sources": item["log_sources"],
                }
            else:
                compact_dc[item["attack_id"]] = item["name"]

        def _build_adj(pairs: List[List[str]]) -> Dict[str, List[str]]:
            adj: Dict[str, List[str]] = {}
            for src, dst in pairs:
                adj.setdefault(src, []).append(dst)
            return adj

        compact_edges = {
            "technique_to_detection_strategy": _build_adj(
                edges_out["technique_to_detection_strategy"]
            ),
            "detection_strategy_to_analytic": _build_adj(
                edges_out["detection_strategy_to_analytic"]
            ),
            "analytic_to_data_component": _build_adj(
                edges_out["analytic_to_data_component"]
            ),
        }

        plat_suffix = (
            f" (filtered by platforms: {', '.join(applied_platforms)})"
            if applied_platforms is not None
            else ""
        )
        compact_resp: Dict[str, Any] = {
            "found": any_resolved,
            "batch": True,
            "detail_level": "compact",
            "domain": dom,
            "count": len(ds_out),
            "counts": {
                "requested_inputs": requested_count,
                "unique_inputs": len(unique_tokens),
                "duplicates_removed": duplicates_removed_count,
                "techniques_total": len(techniques_out),
                "found": found_count,
                "valid_no_detection": no_det_count,
                "not_found": not_found_count,
                "invalid": invalid_count,
                "unavailable": unavail_count,
                "detection_strategies": len(ds_out),
                "analytics": len(an_out),
                "data_components": len(dc_out),
            },
            "duplicates_removed": sorted(dup_tokens),
            "techniques": compact_techniques,
            "coverage": {
                "detection_strategies": compact_ds,
                "analytics": compact_an,
                "data_components": compact_dc,
                "edges": compact_edges,
            },
            "metadata": _build_detection_batch_metadata(
                dom,
                include_description=include_description,
                exists=True,
                detail_level="compact",
                include_log_sources=eff_log_sources,
                applied_platforms=applied_platforms,
                suggested_platforms=batch_suggested_platforms or None,
            ),
            "message": (
                f"Resolved {found_count + no_det_count} of {len(techniques_out)} technique(s) "
                f"in domain '{dom}': {len(ds_out)} unique detection strategy(ies), "
                f"{len(an_out)} analytic(s), {len(dc_out)} data component(s){plat_suffix}.{batch_hint_clause}"
            ),
        }
        if applied_platforms is not None:
            compact_resp["applied_platforms"] = applied_platforms
        if batch_suggested_platforms:
            compact_resp["suggested_platforms"] = batch_suggested_platforms
        return compact_resp

    plat_suffix = (
        f" (filtered by platforms: {', '.join(applied_platforms)})"
        if applied_platforms is not None
        else ""
    )
    full_resp: Dict[str, Any] = {
        "found": any_resolved,
        "batch": True,
        "detail_level": "full",
        "domain": dom,
        "count": len(ds_out),
        "counts": {
            "requested_inputs": requested_count,
            "unique_inputs": len(unique_tokens),
            "duplicates_removed": duplicates_removed_count,
            "techniques_total": len(techniques_out),
            "found": found_count,
            "valid_no_detection": no_det_count,
            "not_found": not_found_count,
            "invalid": invalid_count,
            "unavailable": unavail_count,
            "detection_strategies": len(ds_out),
            "analytics": len(an_out),
            "data_components": len(dc_out),
        },
        "duplicates_removed": sorted(dup_tokens),
        "techniques": techniques_out,
        "coverage": {
            "detection_strategies": ds_out,
            "analytics": an_out,
            "data_components": dc_out,
            "edges": edges_out,
        },
        "metadata": _build_detection_batch_metadata(
            dom,
            include_description=include_description,
            exists=True,
            detail_level="full",
            include_log_sources=True,
            applied_platforms=applied_platforms,
            suggested_platforms=batch_suggested_platforms or None,
        ),
        "message": (
            f"Resolved {found_count + no_det_count} of {len(techniques_out)} technique(s) "
            f"in domain '{dom}': {len(ds_out)} unique detection strategy(ies), "
            f"{len(an_out)} analytic(s), {len(dc_out)} data component(s){plat_suffix}.{batch_hint_clause}"
        ),
    }
    if applied_platforms is not None:
        full_resp["applied_platforms"] = applied_platforms
    if batch_suggested_platforms:
        full_resp["suggested_platforms"] = batch_suggested_platforms
    return full_resp


@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_detection_strategies_for_technique(
    technique_stix_id: str = "",
    domain: str = "enterprise",
    include_description: bool = False,
    technique_ids: Optional[List[str]] = None,
    detail_level: BatchDetailLevel = "compact",
    include_log_sources: bool = False,
    platforms: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Get ATT&CK v20.1 detection strategies (DETxxxx), analytics (ANxxxx), and
    referenced data components (DCxxxx) for one or more techniques.

    Single-technique mode (default when a single ID is passed via `technique_stix_id`
    and `technique_ids` is omitted):
      - Accepts a STIX ID ("attack-pattern--UUID") or ATT&CK ID (e.g., "T1190").
      - Preserves the exact single-technique response schema when `platforms` is omitted.

    Batch mode (triggered when `technique_ids` is provided OR `technique_stix_id`
    contains comma-separated IDs such as "T1190,T1059.001,T1003"):
      - Accepts up to 50 unique technique IDs (ATT&CK IDs and/or STIX IDs).
      - Defaults to `detail_level='compact'` (token-efficient, normalized ID-indexed
        coverage maps and adjacency edges `T->DET->AN->DC`, per-technique statuses,
        platforms, and provenance/caveat metadata).
      - Set `detail_level='full'` for full objects with STIX IDs, per-technique derived
        ID lists, and log sources (or `include_log_sources=True` to add log sources in
        compact mode).

    Platform filtering (supported in both single and batch modes):
      - Pass `platforms=["Linux"]` or `platforms=["Windows", "ESXi"]` to filter
        returned analytics and their referenced data components case-insensitively
        against each analytic's `platforms`. When applied, `applied_platforms` is
        included in the response (and in `metadata` for batch mode).

    Args:
        technique_stix_id: Single technique STIX/ATT&CK ID (e.g., "T1190") or
            comma-separated technique IDs (e.g., "T1190,T1059.001,T1003").
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Whether to include strategy and analytic descriptions.
        technique_ids: Optional list of technique STIX/ATT&CK IDs for batch lookup.
        detail_level: Batch detail level ('compact' default, or 'full'). Ignored in single mode.
        include_log_sources: Include log source names in compact batch mode (always included in 'full').
        platforms: Optional list of platform names (e.g., ['Linux'], ['Windows', 'ESXi'])
            for case-insensitive filtering of analytics and data components.
    """
    is_batch = technique_ids is not None or (
        isinstance(technique_stix_id, str) and "," in technique_stix_id
    )
    if is_batch:
        return _get_detection_strategies_batch(
            technique_stix_id=technique_stix_id,
            technique_ids=technique_ids,
            domain=domain,
            include_description=include_description,
            detail_level=detail_level,
            include_log_sources=include_log_sources,
            platforms=platforms,
        )

    ad = get_attack_data(domain)
    resolved_id, _tech_obj, err = _resolve_stix_object(
        technique_stix_id, domain=domain, expected_stix_type="attack-pattern"
    )
    if resolved_id is None:
        raw_applied = _normalize_detection_platforms(platforms)
        not_found_resp: Dict[str, Any] = {
            "found": False,
            "technique_stix_id": technique_stix_id,
            "domain": domain,
            "count": 0,
            "detection_strategies": [],
            "message": err or f"Technique '{technique_stix_id}' not found in domain '{domain}'.",
        }
        if raw_applied is not None:
            not_found_resp["applied_platforms"] = raw_applied
        return not_found_resp

    technique_stix_id = resolved_id
    v20_idx = _get_v20_detection_index(domain)
    applied_platforms = _normalize_detection_platforms(platforms, v20_idx.get("an_by_id"))
    platform_filter_lower = (
        {p.lower() for p in applied_platforms} if applied_platforms is not None else None
    )
    ds_ids = v20_idx["tech_to_ds"].get(technique_stix_id, [])

    strategies = []
    for ds_id in ds_ids:
        ds_obj = v20_idx["ds_by_id"].get(ds_id)
        if ds_obj is None:
            continue
        try:
            ds_aid = ad.get_attack_id(ds_id)
        except Exception:
            ds_aid = None

        an_list = []
        for an_id in (_stix_get(ds_obj, "x_mitre_analytic_refs") or []):
            an_obj = v20_idx["an_by_id"].get(an_id)
            if an_obj is None:
                continue
            an_platforms = _stix_get(an_obj, "x_mitre_platforms", []) or []
            if platform_filter_lower is not None and not any(
                str(p).strip().lower() in platform_filter_lower
                for p in an_platforms
                if p and str(p).strip()
            ):
                continue
            try:
                an_aid = ad.get_attack_id(an_id)
            except Exception:
                an_aid = None
            dc_refs = []
            for dc_id in v20_idx["an_to_dcs"].get(an_id, []):
                dc_obj = v20_idx["dc_by_id"].get(dc_id)
                try:
                    dc_aid = ad.get_attack_id(dc_id)
                except Exception:
                    dc_aid = None
                dc_refs.append({
                    "attack_id": dc_aid,
                    "name": _stix_get(dc_obj, "name"),
                    "stix_id": dc_id,
                })
            an_list.append({
                "attack_id": an_aid,
                "name": _stix_get(an_obj, "name"),
                "stix_id": an_id,
                "platforms": an_platforms,
                "description": _stix_get(an_obj, "description") if include_description else None,
                "data_components": dc_refs,
            })

        if platform_filter_lower is not None and not an_list:
            continue

        strategies.append({
            "attack_id": ds_aid,
            "name": _stix_get(ds_obj, "name"),
            "stix_id": ds_id,
            "description": _stix_get(ds_obj, "description") if include_description else None,
            "analytics": an_list,
        })

    plat_suffix = (
        f" (filtered by platforms: {', '.join(applied_platforms)})"
        if applied_platforms is not None
        else ""
    )
    single_suggested_platforms: List[str] = []
    if applied_platforms is not None and not strategies:
        available_an_platforms = _extract_available_platforms(
            list(v20_idx.get("an_by_id", {}).values())
        )
        single_suggested_platforms = _suggest_attack_platforms_for_list(
            applied_platforms, available_an_platforms
        )
    single_hint_clause = (
        f" Suggested ATT&CK platform(s): {', '.join(single_suggested_platforms)}."
        if single_suggested_platforms
        else ""
    )
    single_resp: Dict[str, Any] = {
        "found": True,
        "technique_stix_id": technique_stix_id,
        "domain": domain,
        "count": len(strategies),
        "detection_strategies": strategies,
        "message": (
            f"Found {len(strategies)} detection strategy(ies) for "
            f"'{technique_stix_id}' in domain '{domain}'{plat_suffix}.{single_hint_clause}"
        ),
    }
    if applied_platforms is not None:
        single_resp["applied_platforms"] = applied_platforms
    if single_suggested_platforms:
        single_resp["suggested_platforms"] = single_suggested_platforms
    return single_resp


@mcp.tool(annotations=READ_ONLY_LOCAL_ANNOTATIONS)
async def get_analytics(
    domain: str = "enterprise",
    query: str = "",
    limit: Annotated[
        int,
        Field(
            default=DEFAULT_PAGE_LIMIT,
            ge=1,
            le=MAX_PAGE_LIMIT,
            description=f"Maximum number of items to return per page (1-{MAX_PAGE_LIMIT}).",
        ),
    ] = DEFAULT_PAGE_LIMIT,
    offset: Annotated[
        int,
        Field(
            default=0,
            ge=0,
            description="Zero-based starting index for pagination (>= 0).",
        ),
    ] = 0,
    include_description: bool = False,
) -> Dict[str, Any]:
    """
    Search or list ATT&CK v20.1 analytics (x-mitre-analytic / ANxxxx) with pagination.

    Matches exact analytic ATT&CK IDs (e.g., "AN2292") or STIX IDs
    (case-insensitive, surrounding whitespace ignored) as well as case-insensitive
    substring matches in analytic names or descriptions.
    """
    _validate_pagination(limit, offset)
    ad = get_attack_data(domain)
    v20_idx = _get_v20_detection_index(domain)
    q = (query or "").strip().lower()
    an_attack_id_by_id = v20_idx.get("an_attack_id_by_id", {})

    matched = []
    for an_id, an_obj in v20_idx["an_by_id"].items():
        if q:
            an_aid = an_attack_id_by_id.get(an_id) or ""
            name = _stix_get(an_obj, "name", "") or ""
            desc = _stix_get(an_obj, "description", "") or ""
            exact_id_match = (q == str(an_id).lower()) or (bool(an_aid) and q == str(an_aid).lower())
            text_match = (q in name.lower()) or (q in desc.lower())
            if not (exact_id_match or text_match):
                continue
        matched.append((an_id, an_obj))

    matched.sort(key=lambda pair: str(pair[0] or ""))
    page, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        matched, limit=limit, offset=offset
    )

    items = []
    for an_id, an_obj in page:
        an_aid = an_attack_id_by_id.get(an_id)
        if an_aid is None:
            try:
                an_aid = ad.get_attack_id(an_id)
            except Exception:
                an_aid = None
        dc_stix_ids = v20_idx["an_to_dcs"].get(an_id, [])
        resolved_dcs = []
        for dc_id in dc_stix_ids:
            dc_obj = v20_idx["dc_by_id"].get(dc_id)
            try:
                dc_aid = ad.get_attack_id(dc_id)
            except Exception:
                dc_aid = None
            resolved_dcs.append({
                "attack_id": dc_aid,
                "name": _stix_get(dc_obj, "name") if dc_obj is not None else None,
                "stix_id": dc_id,
            })
        items.append({
            "attack_id": an_aid,
            "name": _stix_get(an_obj, "name"),
            "stix_id": an_id,
            "platforms": _stix_get(an_obj, "x_mitre_platforms", []),
            "data_component_refs": dc_stix_ids,
            "data_components": resolved_dcs,
            "description": _stix_get(an_obj, "description") if include_description else None,
        })

    has_more = (safe_offset + len(items)) < total_count
    return {
        "domain": domain,
        "query": query,
        "count": len(items),
        "total_count": total_count,
        "offset": safe_offset,
        "limit": safe_limit,
        "has_more": has_more,
        "next_offset": safe_offset + len(items) if has_more else None,
        "analytics": items,
        "message": f"Showing {len(items)} of {total_count} analytic(s) (offset={safe_offset}) in domain '{domain}'.",
    }


# ---------------------------------------------------------------------------
# Entrypoint for MCP (used by pyproject.toml [project.scripts])
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Entrypoint for the mitre-mcp-server executable.

    - Ensures STIX data is downloaded for all domains (if not already).
    - Starts the FastMCP server so tools (like get_data_stats) can be used.
    """
    import sys
    
    # Log to stderr (visible in Claude Desktop logs)
    print(f"MITRE MCP Server starting...", file=sys.stderr)
    print(f"Data directory: {DATA_DIR}", file=sys.stderr)
    
    # Check if we need to download
    existing = check_existing_data()
    if len(existing) < len(DOMAINS):
        print(f"Downloading MITRE ATT&CK data (version {release_info.LATEST_VERSION})...", file=sys.stderr)
        downloaded = download_all_domains(force=False)
        print(f"Downloaded {len(downloaded)}/{len(DOMAINS)} domains", file=sys.stderr)
    else:
        print(f"Using existing data (version {release_info.LATEST_VERSION})", file=sys.stderr)
    
    # Load domains into memory
    print("Loading domains into memory...", file=sys.stderr)
    loaded = load_all_domains()
    print(f"Loaded {len(loaded)} domains: {', '.join(loaded)}", file=sys.stderr)
    
    print(f"Server ready! (version={SERVER_VERSION})", file=sys.stderr)

    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    if transport in {"http", "streamable-http", "streamable_http"}:
        host = os.getenv("HOST", "127.0.0.1")
        port = int(os.getenv("PORT", "8789"))
        mcp.settings.host = host
        mcp.settings.port = port
        mcp.settings.stateless_http = True
        print(f"Starting mitre-attack-mcp-server on streamable-http at {host}:{port}", file=sys.stderr)
        mcp.run(transport="streamable-http")
    else:
        mcp.run()

if __name__ == "__main__":
    main()