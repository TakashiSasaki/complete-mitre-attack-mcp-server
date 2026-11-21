from __future__ import annotations

from pathlib import Path
from typing import Annotated, List, Tuple, Dict, Any, Optional
import os
import sys

from mitreattack import download_stix, release_info
from mcp.server.fastmcp import FastMCP
from mitreattack.stix20 import MitreAttackData
from pydantic import Field



# ---------------------------------------------------------------------------
# Configuration & shared constants
# ---------------------------------------------------------------------------

# Domains we support
DOMAINS: List[str] = ["enterprise", "mobile", "ics"]

DEFAULT_PAGE_LIMIT = 100
MAX_PAGE_LIMIT = 200


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


def _compute_data_stats() -> Dict[str, Any]:
    """Internal helper: compute statistics about downloaded data."""
    stats: Dict[str, Any] = {}

    for domain in DOMAINS:
        stix_path = get_stix_path(domain)

        if stix_path.exists():
            file_size_mb = stix_path.stat().st_size / (1024 * 1024)
            stats[domain] = {
                "exists": True,
                "path": str(stix_path),
                "size_mb": round(file_size_mb, 2),
                "version": release_info.LATEST_VERSION,
            }
        else:
            stats[domain] = {
                "exists": False,
                "path": None,
                "size_mb": 0.0,
                "version": None,
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

_V20_DETECTION_CACHE: Dict[str, Dict[str, Any]] = {}


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

    ds_by_id = {_stix_get(d, "id"): d for d in det_strategies if _stix_get(d, "id")}
    an_by_id = {_stix_get(a, "id"): a for a in analytics if _stix_get(a, "id")}
    dc_by_id = {_stix_get(c, "id"): c for c in datacomponents if _stix_get(c, "id")}

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

    # Map analytic -> data components
    an_to_dcs: Dict[str, List[str]] = {}
    for an_id, an_obj in an_by_id.items():
        log_refs = _stix_get(an_obj, "x_mitre_log_source_references") or []
        dc_ids: List[str] = []
        for lr in log_refs:
            dc_ref = lr.get("x_mitre_data_component_ref") if isinstance(lr, dict) else getattr(lr, "x_mitre_data_component_ref", None)
            if dc_ref and dc_ref not in dc_ids:
                dc_ids.append(dc_ref)
        an_to_dcs[an_id] = dc_ids

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
        "ds_by_id": ds_by_id,
        "an_by_id": an_by_id,
        "dc_by_id": dc_by_id,
        "tech_to_ds": tech_to_ds,
        "ds_to_tech": ds_to_tech,
        "an_to_dcs": an_to_dcs,
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
        aliases = _stix_get(obj, "aliases")
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


@mcp.tool()
async def get_data_stats() -> Dict[str, Any]:
    """
    Return statistics about downloaded MITRE ATT&CK STIX data.

    This confirms which domains are present on disk, their file paths,
    sizes, and ATT&CK release version. It assumes that downloads have
    already been attempted at server startup.
    """
    return _compute_data_stats()

@mcp.tool()
async def get_technique_by_id(
    technique_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
    ) -> Dict[str, Any]:

    """" 
    Retrieve a MITRE ATT&CK technique by its external ATT&CK ID (e.g., "T1055", "T1053.005").

    This tool searches the specified ATT&CK domain (enterprise, mobile, or ics)
    and returns both structured machine-readable data and an optional formatted
    human-readable text block. It is useful for user-facing responses as well
    as downstream programmatic reasoning.

    Args:
        technique_id: The external ATT&CK technique ID (e.g., "T1055").
        domain: ATT&CK domain to search in ("enterprise", "mobile", "ics").
        include_description: If True, returns the full ATT&CK description text.

    Returns:
        {
          "found": bool,
          "technique": {
              "id": "<ATT&CK ID>",
              "name": "<technique name>",
              "stix_id": "<STIX object ID>",
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

    formatted = format_objects(
        [tech],
        include_description=include_description,
        domain=domain
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
            "revoked": is_revoked,
            "deprecated": is_deprecated,
            "revoked_by": revoked_by,
            "description": _stix_get(tech, "description") if include_description else None,
        },
        "formatted": formatted,
        "message": msg,
    }

@mcp.tool()
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

    try:
        obj = attack_data.get_object_by_attack_id(attack_id, stix_type)
    except Exception:
        obj = None

    if obj is None:
        return {
            "found": False,
            "object": None,
            "formatted": "",
            "message": (
                f"No object found for ATT&CK ID '{attack_id}' with STIX type "
                f"'{stix_type}' in domain '{domain}'."
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

    formatted = format_objects(
        [obj],
        include_description=include_description,
        domain=domain,
    )

    return {
        "found": True,
        "object": {
            "id": attack_id,
            "name": name,
            "stix_id": stix_id,
            "type": stix_type,
            "description": description,
        },
        "formatted": formatted,
        "message": f"Object found for ATT&CK ID '{attack_id}' in domain '{domain}'.",
    }

@mcp.tool()
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

@mcp.tool()
async def get_objects_by_name(
    name: str,
    stix_type: str,
    domain: str = "enterprise",
    include_description: bool = False,
) -> Dict[str, Any]:
    """
    Retrieve MITRE ATT&CK objects by exact name match (case-sensitive).

    This tool performs an exact name match for a specific STIX type within
    a given ATT&CK domain. It is more strict than generic search methods,
    which typically perform partial or keyword matching.

    Examples:
        - Technique: get_objects_by_name("Phishing", "attack-pattern")
        - Group: get_objects_by_name("APT29", "intrusion-set")
        - Malware: get_objects_by_name("Cobalt Strike", "malware")

    Args:
        name: Exact object name to search for (case-sensitive).
        stix_type: STIX object type (same values as get_object_by_attack_id),
                   e.g. "attack-pattern", "intrusion-set", "malware",
                   "tool", "course-of-action", etc.
        domain: ATT&CK domain ("enterprise", "mobile", or "ics").
        include_description: Whether to include descriptions in the formatted output
                             and structured result.

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

    try:
        objs = attack_data.get_objects_by_name(name, stix_type)
    except Exception:
        objs = []

    if not objs:
        return {
            "count": 0,
            "objects": [],
            "formatted": "",
            "message": (
                f"No objects found with name '{name}' and type '{stix_type}' "
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

@mcp.tool()
async def get_objects_by_content(
    content: str,
    object_type: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Search MITRE ATT&CK objects by matching text inside their description field.

    This performs a full-text search over object descriptions. It is useful for:
      • Finding techniques related to specific technologies (e.g., “PowerShell”)
      • Finding groups mentioning a region or country (e.g., “Russia”)
      • Finding mitigations referencing specific defenses (e.g., “multi-factor”)
      • Searching malware or tool descriptions for keywords

    Args:
        content: The text to search for (case-insensitive, partial match).
        object_type: STIX object type, such as:
            - "attack-pattern" (techniques)
            - "intrusion-set" (APT groups)
            - "malware"
            - "tool"
            - "course-of-action" (mitigations)
            - "campaign"
            - "x-mitre-data-source"
            - "x-mitre-data-component"
            - etc.
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to return descriptions in the structured output.

    Returns:
        {
          "count": <number of matches>,
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

    # Perform text search
    try:
        objs = attack_data.get_objects_by_content(content, object_type)
    except Exception:
        objs = []

    if not objs:
        return {
            "count": 0,
            "objects": [],
            "formatted": "",
            "message": (
                f"No {object_type} objects in domain '{domain}' contain the text '{content}'."
            ),
        }

    structured: List[Dict[str, Any]] = []

    for obj in objs:
        # Handle STIX objects that may be dict-like or class-like
        if isinstance(obj, dict):
            name = obj.get("name")
            stix_id = obj.get("id")
            stix_type = obj.get("type", object_type)
            description = obj.get("description") if include_description else None
        else:
            name = getattr(obj, "name", None)
            stix_id = getattr(obj, "id", None)
            stix_type = getattr(obj, "type", object_type)
            description = getattr(obj, "description", None) if include_description else None

        # Resolve external ATT&CK ID, if present
        try:
            attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            attack_id = None

        structured.append(
            {
                "attack_id": attack_id,
                "name": name,
                "stix_id": stix_id,
                "type": stix_type,
                "description": description,
            }
        )

    # Human-readable output using your formatter
    formatted = format_objects(
        objs,
        include_description=include_description,
        domain=domain,
    )

    return {
        "count": len(structured),
        "objects": structured,
        "formatted": formatted,
        "message": (
            f"Found {len(structured)} '{object_type}' objects whose descriptions "
            f"contain the text '{content}'."
        ),
    }

@mcp.tool()
async def get_techniques_by_tactic(
    tactic: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all techniques associated with a specific ATT&CK tactic.

    This uses the MITRE ATT&CK Navigator-style mapping between tactics and
    techniques for a given domain (e.g., "enterprise-attack").

    Examples:
        - get_techniques_by_tactic("Initial Access", "enterprise")
        - get_techniques_by_tactic("Execution", "enterprise")
        - get_techniques_by_tactic("Persistence", "enterprise")

    Args:
        tactic: Tactic name (e.g., "Initial Access", "Persistence").
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include technique descriptions
                             in the structured and formatted output.

    Returns:
        {
          "count": <number of techniques>,
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

    tactic_shortname = _normalize_tactic_shortname(attack_data, tactic)
    try:
        techniques = attack_data.get_techniques_by_tactic(
            tactic_shortname,
            f"{domain}-attack",
            remove_revoked_deprecated=True,
        )
    except Exception:
        techniques = []

    if not techniques:
        legacy = _LEGACY_TACTIC_MIGRATIONS.get((tactic or "").strip().lower())
        msg = f"No techniques found for tactic '{tactic}' in domain '{domain}'."
        resp: Dict[str, Any] = {
            "count": 0,
            "techniques": [],
            "formatted": "",
            "message": f"{msg} {legacy['hint']}" if legacy else msg,
        }
        if legacy:
            resp["suggested_tactics"] = legacy["suggested_tactics"]
        return resp

    structured: List[Dict[str, Any]] = []

    for tech in techniques:
        # Handle dict-like vs object-like STIX representations
        if isinstance(tech, dict):
            name = tech.get("name")
            stix_id = tech.get("id")
            description = tech.get("description") if include_description else None
        else:
            name = getattr(tech, "name", None)
            stix_id = getattr(tech, "id", None)
            description = getattr(tech, "description", None) if include_description else None

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
                "tactic": tactic,
            }
        )

    formatted = format_objects(
        techniques,
        include_description=include_description,
        domain=domain,
    )

    return {
        "count": len(structured),
        "techniques": structured,
        "formatted": formatted,
        "message": (
            f"Found {len(structured)} technique(s) for tactic '{tactic}' "
            f"in domain '{domain}'."
        ),
    }

@mcp.tool()
async def search_techniques(
    query: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Search MITRE ATT&CK techniques by keyword in their name or description.

    This tool performs a case-insensitive search over all non-revoked,
    non-deprecated techniques in the given domain. A technique is matched if
    the query string appears in either:
      • the technique name, or
      • the technique description

    Examples:
        - search_techniques("PowerShell")
        - search_techniques("credential dumping")
        - search_techniques("initial access", domain="enterprise")

    Args:
        query: Text to search for in technique names and descriptions.
        domain: ATT&CK domain ("enterprise", "mobile", or "ics").
        include_description: Whether to include descriptions in the structured
                             result and formatted output.

    Returns:
        {
          "count": <number of matches>,
          "techniques": [
            {
              "attack_id": "<TXXXX or TXXXX.YYY>",
              "name": "<technique name>",
              "stix_id": "<attack-pattern--...>",
              "description": "<description or null>",
            },
            ...
          ],
          "formatted": "<human-readable formatted list>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)

    try:
        all_techniques = attack_data.get_techniques(remove_revoked_deprecated=True)
    except Exception:
        all_techniques = []

    query_lower = query.lower()
    matched: List[Any] = []

    for tech in all_techniques:
        # Handle dict-like vs object-like STIX representations
        if isinstance(tech, dict):
            name = tech.get("name") or ""
            description = tech.get("description") or ""
        else:
            name = getattr(tech, "name", "") or ""
            description = getattr(tech, "description", "") or ""

        if query_lower in name.lower() or query_lower in description.lower():
            matched.append(tech)

    if not matched:
        return {
            "count": 0,
            "techniques": [],
            "formatted": "",
            "message": (
                f"No techniques in domain '{domain}' matched the query '{query}'."
            ),
        }

    structured: List[Dict[str, Any]] = []

    for tech in matched:
        if isinstance(tech, dict):
            name = tech.get("name")
            stix_id = tech.get("id")
            description = tech.get("description") if include_description else None
        else:
            name = getattr(tech, "name", None)
            stix_id = getattr(tech, "id", None)
            description = getattr(tech, "description", None) if include_description else None

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

    formatted = format_objects(
        matched,
        include_description=include_description,
        domain=domain,
    )

    return {
        "count": len(structured),
        "techniques": structured,
        "formatted": formatted,
        "message": (
            f"Found {len(structured)} technique(s) in domain '{domain}' "
            f"matching query '{query}'."
        ),
    }

@mcp.tool()
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

@mcp.tool()
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

@mcp.tool()
async def search_groups(
    query: str = "",
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Search MITRE ATT&CK intrusion sets (APT groups) by name, alias, or
    description (case-insensitive).

    If the query is empty, all groups in the domain are returned.

    Args:
        query: Search keyword (name, alias, or any text in the description).
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include descriptions in the output.

    Returns:
        {
          "count": <number of matches>,
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

    try:
        groups = attack_data.get_groups(remove_revoked_deprecated=True)
    except Exception:
        groups = []

    # Empty query → return all groups
    query_lower = query.lower().strip()
    matched = []

    for grp in groups:
        # extract fields safely
        if isinstance(grp, dict):
            name = grp.get("name", "").lower()
            description = grp.get("description", "").lower()
            aliases = [a.lower() for a in grp.get("aliases", [])]
        else:
            name = getattr(grp, "name", "").lower()
            description = getattr(grp, "description", "").lower()
            aliases = [a.lower() for a in getattr(grp, "aliases", [])]

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
            "groups": [],
            "formatted": "",
            "message": f"No APT groups in domain '{domain}' matched query '{query}'.",
        }

    # Build structured output
    response_groups = []
    for grp in matched:
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

        # Resolve ATT&CK external ID (e.g., G0016)
        try:
            attack_id = attack_data.get_attack_id(stix_id)
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

    formatted = format_objects(
        matched,
        include_description=include_description,
        domain=domain,
    )

    return {
        "count": len(response_groups),
        "groups": response_groups,
        "formatted": formatted,
        "message": (
            f"Found {len(response_groups)} APT group(s) in domain '{domain}' "
            f"matching query '{query}'."
        ),
    }

@mcp.tool()
async def get_group_techniques(
    group_name: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all techniques used by a specific APT group (intrusion set).

    This tool:
      1) Locates a group by name or alias (case-insensitive, partial match).
      2) Uses MITRE's get_techniques_used_by_group() to retrieve techniques
         related to that group (via 'uses' relationships).

    Args:
        group_name: Group name or alias (e.g., "APT29", "Lazarus Group").
        domain: ATT&CK domain ("enterprise", "mobile", or "ics").
        include_description: Whether to include descriptions in the output.

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
          "count": <number of techniques>,
          "techniques": [
            {
              "attack_id": "TXXXX or TXXXX.YYY",
              "name": "...",
              "stix_id": "attack-pattern--...",
              "description": "..." | null,
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
    attack_data = get_attack_data(domain)

    # --- 1) Find the group by name or alias (same semantics as get_group_by_name) ---
    try:
        groups = attack_data.get_groups(remove_revoked_deprecated=True)
    except Exception:
        groups = []

    query = group_name.lower()
    group = None

    for grp in groups:
        if isinstance(grp, dict):
            name = (grp.get("name") or "").lower()
            aliases = [a.lower() for a in grp.get("aliases", [])]
        else:
            name = (getattr(grp, "name", "") or "").lower()
            aliases = [a.lower() for a in getattr(grp, "aliases", [])]

        if query in name or any(query in alias for alias in aliases):
            group = grp
            break

    if group is None:
        return {
            "found": False,
            "group": None,
            "count": 0,
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

    techniques_structured: List[Dict[str, Any]] = []
    technique_objects_for_format: List[Any] = []

    for entry in rel_entries:
        # Defensive: handle dict vs object
        if isinstance(entry, dict):
            tech_obj = entry.get("object")
            rels = entry.get("relationships", [])
        else:
            # If the library ever changes the type, be conservative
            tech_obj = getattr(entry, "object", None)
            rels = getattr(entry, "relationships", [])

        if tech_obj is None:
            continue

        technique_objects_for_format.append(tech_obj)

        # Extract technique fields
        if isinstance(tech_obj, dict):
            t_name = tech_obj.get("name")
            t_stix_id = tech_obj.get("id")
            t_desc = tech_obj.get("description") if include_description else None
        else:
            t_name = getattr(tech_obj, "name", None)
            t_stix_id = getattr(tech_obj, "id", None)
            t_desc = getattr(tech_obj, "description", None) if include_description else None

        # ATT&CK external ID (TXXXX / TXXXX.YYY)
        try:
            t_attack_id = attack_data.get_attack_id(t_stix_id)
        except Exception:
            t_attack_id = None

        # Compact relationship info
        relationships_info = []
        for r in rels:
            if isinstance(r, dict):
                r_id = r.get("id")
                r_type = r.get("relationship_type")
                r_desc = r.get("description")
                r_source = r.get("source_ref")
                r_target = r.get("target_ref")
            else:
                r_id = getattr(r, "id", None)
                r_type = getattr(r, "relationship_type", None)
                r_desc = getattr(r, "description", None)
                r_source = getattr(r, "source_ref", None)
                r_target = getattr(r, "target_ref", None)

            relationships_info.append(
                {
                    "stix_id": r_id,
                    "relationship_type": r_type,
                    "description": r_desc,
                    "source_ref": r_source,
                    "target_ref": r_target,
                }
            )

        techniques_structured.append(
            {
                "attack_id": t_attack_id,
                "name": t_name,
                "stix_id": t_stix_id,
                "description": t_desc,
                "relationships": relationships_info,
            }
        )

    # Human-readable formatted list of techniques (ignore relationship metadata there)
    formatted = ""
    if technique_objects_for_format:
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
        "techniques": techniques_structured,
        "formatted": formatted,
        "message": (
            f"Found {len(techniques_structured)} technique(s) used by group "
            f"'{group_name}' in domain '{domain}'."
        ),
    }

@mcp.tool()
async def get_software(
    domain: str = "enterprise",
    include_description: bool = False,
) -> Dict[str, Any]:
    """
    Get all software (malware and tools) in a given ATT&CK domain.

    This returns non-revoked, non-deprecated software objects, including
    both malware and tools, as defined by the MITRE ATT&CK dataset.

    Args:
        domain: ATT&CK domain to search ("enterprise", "mobile", or "ics").
        include_description: Whether to include descriptions in the output and
                             formatted text.

    Returns:
        {
          "count": <number of software objects>,
          "software": [
            {
              "attack_id": "<SXXXX or similar, if present>",
              "name": "<software name>",
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

    try:
        software_objs = attack_data.get_software(remove_revoked_deprecated=True)
    except Exception:
        software_objs = []

    if not software_objs:
        return {
            "count": 0,
            "software": [],
            "formatted": "",
            "message": f"No software objects found in domain '{domain}'.",
        }

    software_list: List[Dict[str, Any]] = []

    for obj in software_objs:
        if isinstance(obj, dict):
            name = obj.get("name")
            stix_id = obj.get("id")
            stix_type = obj.get("type")
            description = obj.get("description") if include_description else None
        else:
            name = getattr(obj, "name", None)
            stix_id = getattr(obj, "id", None)
            stix_type = getattr(obj, "type", None)
            description = getattr(obj, "description", None) if include_description else None

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
                "stix_id": stix_id,
                "type": stix_type,
                "description": description,
            }
        )

    formatted = format_objects(
        software_objs,
        include_description=include_description,
        domain=domain,
    )

    return {
        "count": len(software_list),
        "software": software_list,
        "formatted": formatted,
        "message": (
            f"Found {len(software_list)} software object(s) "
            f"in domain '{domain}'."
        ),
    }

@mcp.tool()
async def search_software(
    query: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Search MITRE ATT&CK software (malware & tools) by keyword in name or
    description (case-insensitive).

    Args:
        query: Keyword to search for in software names and descriptions.
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include descriptions in the response.

    Returns:
        {
          "count": <number of matches>,
          "software": [
            {
              "attack_id": "<SXXXX or similar>",
              "name": "...",
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

    # Load all software objects
    try:
        all_sw = attack_data.get_software(remove_revoked_deprecated=True)
    except Exception:
        all_sw = []

    if not all_sw:
        return {
            "count": 0,
            "software": [],
            "formatted": "",
            "message": f"No software found in domain '{domain}'.",
        }

    query_lower = query.lower()
    matched = []

    # Software search loop
    for sw in all_sw:
        if isinstance(sw, dict):
            name = (sw.get("name") or "").lower()
            description = (sw.get("description") or "").lower()
        else:
            name = (getattr(sw, "name", "") or "").lower()
            description = (getattr(sw, "description", "") or "").lower()

        if query_lower in name or query_lower in description:
            matched.append(sw)

    if not matched:
        return {
            "count": 0,
            "software": [],
            "formatted": "",
            "message": (
                f"No software objects in domain '{domain}' matched query '{query}'."
            ),
        }

    # Build structured output
    structured = []

    for sw in matched:
        if isinstance(sw, dict):
            name = sw.get("name")
            stix_id = sw.get("id")
            sw_type = sw.get("type")
            desc = sw.get("description") if include_description else None
        else:
            name = getattr(sw, "name", None)
            stix_id = getattr(sw, "id", None)
            sw_type = getattr(sw, "type", None)
            desc = getattr(sw, "description", None) if include_description else None

        # ATT&CK external ID (SXXXX)
        try:
            attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            attack_id = None

        structured.append(
            {
                "attack_id": attack_id,
                "name": name,
                "stix_id": stix_id,
                "type": sw_type,
                "description": desc,
            }
        )

    formatted = format_objects(
        matched,
        include_description=include_description,
        domain=domain,
    )

    return {
        "count": len(structured),
        "software": structured,
        "formatted": formatted,
        "message": (
            f"Found {len(structured)} software object(s) in domain '{domain}' "
            f"matching '{query}'."
        ),
    }

@mcp.tool()
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

@mcp.tool()
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

@mcp.tool()
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

    # 1) Look up the technique by ATT&CK ID
    try:
        tech = attack_data.get_object_by_attack_id(technique_id, "attack-pattern")
    except Exception:
        tech = None

    if tech is None:
        return {
            "found": False,
            "technique": None,
            "tactics": [],
            "message": (
                f"Technique '{technique_id}' not found in domain '{domain}'."
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
            "id": technique_id,
            "name": tech_name,
            "stix_id": tech_stix_id,
        },
        "tactics": tactics,
        "message": (
            f"Found {len(tactics)} tactic phase(s) for technique '{technique_id}' "
            f"in domain '{domain}'."
        ),
    }

@mcp.tool()
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
    attack_data = get_attack_data(domain)

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
        "domain": domain,
        "stats": stats,
        "message": (
            f"ATT&CK object statistics for domain '{domain}': "
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

@mcp.tool()
async def get_groups_by_alias(
    alias: str,
    domain: str = "enterprise",
    include_description: bool = True,
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

    try:
        raw_groups = attack_data.get_groups_by_alias(alias) or []
    except Exception:
        raw_groups = []

    if not raw_groups and alias:
        alias_norm = alias.strip().lower()
        try:
            all_groups = attack_data.get_groups(remove_revoked_deprecated=True) or []
            raw_groups = [
                g for g in all_groups
                if alias_norm == (_stix_get(g, "name", "") or "").lower()
                or any(alias_norm == (a or "").lower() for a in (_stix_get(g, "aliases", []) or []))
            ]
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

@mcp.tool()
async def get_techniques_used_by_group(
    group_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all techniques used by a specific APT group, identified by its STIX ID.

    This is similar to `get_group_techniques`, but instead of a group name or
    alias it takes the group's STIX UUID (e.g. "intrusion-set--..."), which is
    useful when you already have the STIX ID from another query or relationship.

    Args:
        group_stix_id: STIX ID of the group (intrusion-set--UUID).
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include technique descriptions.

    Returns:
        {
          "group": {
              "attack_id": "GXXXX" | null,
              "name": "<group name or null>",
              "stix_id": "<intrusion-set--UUID>",
              "description": "<text or null>"
          } | null,
          "count": <number of techniques>,
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
    attack_data = get_attack_data(domain)

    # Try to resolve basic group info from its STIX ID (optional but useful)
    try:
        grp_obj = attack_data.get_object_by_stix_id(group_stix_id)
    except Exception:
        grp_obj = None

    group_info: Optional[Dict[str, Any]] = None
    if grp_obj is not None:
        if isinstance(grp_obj, dict):
            g_name = grp_obj.get("name")
            g_desc = grp_obj.get("description") if include_description else None
        else:
            g_name = getattr(grp_obj, "name", None)
            g_desc = getattr(grp_obj, "description", None) if include_description else None

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
            "group": group_info,
            "count": 0,
            "techniques": [],
            "formatted": "",
            "message": (
                f"No techniques found for group STIX ID '{group_stix_id}' "
                f"in domain '{domain}'."
            ),
        }

    techniques_structured: List[Dict[str, Any]] = []
    technique_objects_for_format: List[Any] = []

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

        technique_objects_for_format.append(tech_obj)

        # Technique fields
        if isinstance(tech_obj, dict):
            t_name = tech_obj.get("name")
            t_stix_id = tech_obj.get("id")
            t_desc = tech_obj.get("description") if include_description else None
        else:
            t_name = getattr(tech_obj, "name", None)
            t_stix_id = getattr(tech_obj, "id", None)
            t_desc = getattr(tech_obj, "description", None) if include_description else None

        try:
            t_attack_id = attack_data.get_attack_id(t_stix_id)
        except Exception:
            t_attack_id = None

        # Relationship info
        relationships_info = []
        for r in rels:
            if isinstance(r, dict):
                r_id = r.get("id")
                r_type = r.get("relationship_type")
                r_desc = r.get("description")
                r_source = r.get("source_ref")
                r_target = r.get("target_ref")
            else:
                r_id = getattr(r, "id", None)
                r_type = getattr(r, "relationship_type", None)
                r_desc = getattr(r, "description", None)
                r_source = getattr(r, "source_ref", None)
                r_target = getattr(r, "target_ref", None)

            relationships_info.append(
                {
                    "stix_id": r_id,
                    "relationship_type": r_type,
                    "description": r_desc,
                    "source_ref": r_source,
                    "target_ref": r_target,
                }
            )

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
    if technique_objects_for_format:
        formatted = format_objects(
            technique_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "group": group_info,
        "count": len(techniques_structured),
        "techniques": techniques_structured,
        "formatted": formatted,
        "message": (
            f"Found {len(techniques_structured)} technique(s) for group STIX ID "
            f"'{group_stix_id}' in domain '{domain}'."
        ),
    }

@mcp.tool()
async def get_software_used_by_group(
    group_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all software (malware and tools) used by a specific APT group,
    identified by its STIX ID.

    This uses MITRE's `get_software_used_by_group` to follow 'uses'
    relationships from an intrusion set (group) to software objects.

    Args:
        group_stix_id: STIX ID of the group (e.g., "intrusion-set--UUID").
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include software descriptions.

    Returns:
        {
          "group": {
              "attack_id": "GXXXX" | null,
              "name": "<group name or null>",
              "stix_id": "<intrusion-set--UUID>",
              "description": "<text or null>"
          } | null,
          "count": <number of software objects>,
          "software": [
            {
              "attack_id": "SXXXX or similar" | null,
              "name": "<software name>",
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
    attack_data = get_attack_data(domain)

    # Optional: resolve group info from its STIX ID
    try:
        grp_obj = attack_data.get_object_by_stix_id(group_stix_id)
    except Exception:
        grp_obj = None

    group_info: Optional[Dict[str, Any]] = None
    if grp_obj is not None:
        if isinstance(grp_obj, dict):
            g_name = grp_obj.get("name")
            g_desc = grp_obj.get("description") if include_description else None
        else:
            g_name = getattr(grp_obj, "name", None)
            g_desc = getattr(grp_obj, "description", None) if include_description else None

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
            "group": group_info,
            "count": 0,
            "software": [],
            "formatted": "",
            "message": (
                f"No software found for group STIX ID '{group_stix_id}' "
                f"in domain '{domain}'."
            ),
        }

    software_structured: List[Dict[str, Any]] = []
    software_objects_for_format: List[Any] = []

    for entry in rel_entries:
        if isinstance(entry, dict):
            sw_obj = entry.get("object")
            rels = entry.get("relationships", [])
        else:
            sw_obj = getattr(entry, "object", None)
            rels = getattr(entry, "relationships", [])

        if sw_obj is None:
            continue

        software_objects_for_format.append(sw_obj)

        # Extract software fields
        if isinstance(sw_obj, dict):
            s_name = sw_obj.get("name")
            s_stix_id = sw_obj.get("id")
            s_type = sw_obj.get("type")
            s_desc = sw_obj.get("description") if include_description else None
        else:
            s_name = getattr(sw_obj, "name", None)
            s_stix_id = getattr(sw_obj, "id", None)
            s_type = getattr(sw_obj, "type", None)
            s_desc = getattr(sw_obj, "description", None) if include_description else None

        # ATT&CK external ID (SXXXX, or sometimes none)
        try:
            s_attack_id = attack_data.get_attack_id(s_stix_id)
        except Exception:
            s_attack_id = None

        relationships_info = []
        for r in rels:
            if isinstance(r, dict):
                r_id = r.get("id")
                r_type = r.get("relationship_type")
                r_desc = r.get("description")
                r_source = r.get("source_ref")
                r_target = r.get("target_ref")
            else:
                r_id = getattr(r, "id", None)
                r_type = getattr(r, "relationship_type", None)
                r_desc = getattr(r, "description", None)
                r_source = getattr(r, "source_ref", None)
                r_target = getattr(r, "target_ref", None)

            relationships_info.append(
                {
                    "stix_id": r_id,
                    "relationship_type": r_type,
                    "description": r_desc,
                    "source_ref": r_source,
                    "target_ref": r_target,
                }
            )

        software_structured.append(
            {
                "attack_id": s_attack_id,
                "name": s_name,
                "stix_id": s_stix_id,
                "type": s_type,
                "description": s_desc,
                "relationships": relationships_info,
            }
        )

    formatted = ""
    if software_objects_for_format:
        formatted = format_objects(
            software_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "group": group_info,
        "count": len(software_structured),
        "software": software_structured,
        "formatted": formatted,
        "message": (
            f"Found {len(software_structured)} software object(s) used by group "
            f"STIX ID '{group_stix_id}' in domain '{domain}'."
        ),
    }


# ---------------------------------------------------------------------------
# Campaign lookup
# ---------------------------------------------------------------------------

@mcp.tool()
async def get_campaigns_attributed_to_group(
    group_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all campaigns attributed to a specific intrusion set (APT group),
    identified by its STIX ID.

    Campaigns represent specific operations or intrusion events attributed
    to a threat group.

    Args:
        group_stix_id: STIX UUID of the group (e.g., "intrusion-set--UUID").
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include campaign descriptions.

    Returns:
        {
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

    # Optional: resolve group details
    try:
        grp_obj = attack_data.get_object_by_stix_id(group_stix_id)
    except Exception:
        grp_obj = None

    group_info = None
    if grp_obj is not None:
        if isinstance(grp_obj, dict):
            g_name = grp_obj.get("name")
            g_desc = grp_obj.get("description") if include_description else None
        else:
            g_name = getattr(grp_obj, "name", None)
            g_desc = getattr(grp_obj, "description", None) if include_description else None

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
                "stix_id": stix_id,
                "description": desc,
            }
        )

    formatted = format_objects(
        campaign_objects_for_format,
        include_description=include_description,
        domain=domain,
    )

    return {
        "group": group_info,
        "count": len(structured_campaigns),
        "campaigns": structured_campaigns,
        "formatted": formatted,
        "message": (
            f"Found {len(structured_campaigns)} campaign(s) attributed to group "
            f"STIX ID '{group_stix_id}' in domain '{domain}'."
        ),
    }

@mcp.tool()
async def get_campaigns_by_alias(
    alias: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get campaigns by their alias.

    Campaigns frequently have multiple names assigned by different vendors
    or research teams. This function resolves those aliases.

    Args:
        alias: Campaign alias or alternate name (case-insensitive)
        domain: ATT&CK domain ("enterprise", "ics", etc.)
        include_description: Include campaign descriptions in output

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

    # Retrieve matching campaigns
    try:
        campaigns = attack_data.get_campaigns_by_alias(alias) or []
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
        name = getattr(c, "name", None)
        stix_id = getattr(c, "id", None)

        try:
            attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            attack_id = None

        description = getattr(c, "description", None) if include_description else None

        campaign_entries.append(
            {
                "name": name,
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


@mcp.tool()
async def get_techniques_used_by_group_software(
    group_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get techniques used by the software that a group uses (Group → Software → Techniques).

    This provides an indirect view of a group's capabilities by following:
        Group (intrusion set) → Software (malware/tools) → Techniques

    Args:
        group_stix_id: STIX ID of the group (e.g., "intrusion-set--UUID").
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include technique descriptions.

    Returns:
        {
          "group": {
              "attack_id": "GXXXX" | null,
              "name": "<group name or null>",
              "stix_id": "<intrusion-set--UUID>",
              "description": "<text or null>",
          } | null,

          "count": <number of techniques>,

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
    attack_data = get_attack_data(domain)

    # Optional: resolve group details for context
    try:
        grp_obj = attack_data.get_object_by_stix_id(group_stix_id)
    except Exception:
        grp_obj = None

    group_info: Optional[Dict[str, Any]] = None
    if grp_obj is not None:
        if isinstance(grp_obj, dict):
            g_name = grp_obj.get("name")
            g_desc = grp_obj.get("description") if include_description else None
        else:
            g_name = getattr(grp_obj, "name", None)
            g_desc = getattr(grp_obj, "description", None) if include_description else None

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
            "group": group_info,
            "count": 0,
            "techniques": [],
            "formatted": "",
            "message": (
                f"No techniques found via software used by group STIX ID "
                f"'{group_stix_id}' in domain '{domain}'."
            ),
        }

    techniques_structured: List[Dict[str, Any]] = []
    technique_objects_for_format: List[Any] = []

    for t_stix_id, tech_obj in sorted(
        tech_by_id.items(),
        key=lambda item: (str(_stix_get(item[1], "name") or ""), str(item[0])),
    ):
        technique_objects_for_format.append(tech_obj)

        t_name = _stix_get(tech_obj, "name")
        t_desc = _stix_get(tech_obj, "description") if include_description else None
        try:
            t_attack_id = attack_data.get_attack_id(t_stix_id)
        except Exception:
            t_attack_id = None

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
                "relationships": rels_sorted,
                "provenance_paths": paths_sorted,
            }
        )

    formatted = ""
    if technique_objects_for_format:
        formatted = format_objects(
            technique_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "group": group_info,
        "count": len(techniques_structured),
        "techniques": techniques_structured,
        "formatted": formatted,
        "message": (
            f"Found {len(techniques_structured)} technique(s) reachable via software "
            f"used by group STIX ID '{group_stix_id}' in domain '{domain}'."
        ),
    }

@mcp.tool()
async def get_groups_using_technique(
    technique_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all APT groups (intrusion sets) that use a specific technique.

    This is a reverse lookup: Technique → Groups.
    It follows 'uses' relationships from a technique STIX ID to intrusion sets.

    Args:
        technique_stix_id: STIX ID of the technique
                           (e.g., "attack-pattern--UUID").
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include group descriptions.

    Returns:
        {
          "technique": {
              "attack_id": "TXXXX or TXXXX.YYY" | null,
              "name": "<technique name or null>",
              "stix_id": "<attack-pattern--UUID>",
              "description": "<text or null>",
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
    attack_data = get_attack_data(domain)

    # Optional: resolve technique metadata
    try:
        tech_obj = attack_data.get_object_by_stix_id(technique_stix_id)
    except Exception:
        tech_obj = None

    technique_info: Optional[Dict[str, Any]] = None
    if tech_obj is not None:
        if isinstance(tech_obj, dict):
            t_name = tech_obj.get("name")
            t_desc = tech_obj.get("description") if include_description else None
        else:
            t_name = getattr(tech_obj, "name", None)
            t_desc = getattr(tech_obj, "description", None) if include_description else None

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
            "technique": technique_info,
            "count": 0,
            "groups": [],
            "formatted": "",
            "message": (
                f"No groups found using technique STIX ID '{technique_stix_id}' "
                f"in domain '{domain}'."
            ),
        }

    groups_structured: List[Dict[str, Any]] = []
    group_objects_for_format: List[Any] = []

    for entry in rel_entries:
        # Some APIs may return RelationshipEntry-like objects with .object/.relationships,
        # others may return plain group objects. Handle both defensively.
        if isinstance(entry, dict) and ("object" in entry or "relationships" in entry):
            grp_obj = entry.get("object", entry)
            rels = entry.get("relationships", [])
        else:
            # Could be an object with attributes or a bare dict group
            grp_obj = entry
            rels = []

        if grp_obj is None:
            continue

        group_objects_for_format.append(grp_obj)

        # Extract group fields
        if isinstance(grp_obj, dict):
            g_name = grp_obj.get("name")
            g_stix_id = grp_obj.get("id")
            g_aliases = grp_obj.get("aliases", [])
            g_desc = grp_obj.get("description") if include_description else None
        else:
            g_name = getattr(grp_obj, "name", None)
            g_stix_id = getattr(grp_obj, "id", None)
            g_aliases = getattr(grp_obj, "aliases", [])
            g_desc = getattr(grp_obj, "description", None) if include_description else None

        # External ATT&CK ID (GXXXX)
        try:
            g_attack_id = attack_data.get_attack_id(g_stix_id)
        except Exception:
            g_attack_id = None

        relationships_info = []
        for r in rels:
            if isinstance(r, dict):
                r_id = r.get("id")
                r_type = r.get("relationship_type")
                r_desc = r.get("description")
                r_source = r.get("source_ref")
                r_target = r.get("target_ref")
            else:
                r_id = getattr(r, "id", None)
                r_type = getattr(r, "relationship_type", None)
                r_desc = getattr(r, "description", None)
                r_source = getattr(r, "source_ref", None)
                r_target = getattr(r, "target_ref", None)

            relationships_info.append(
                {
                    "stix_id": r_id,
                    "relationship_type": r_type,
                    "description": r_desc,
                    "source_ref": r_source,
                    "target_ref": r_target,
                }
            )

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

    # Nicely formatted human-readable block
    formatted = ""
    if group_objects_for_format:
        formatted = format_objects(
            group_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "technique": technique_info,
        "count": len(groups_structured),
        "groups": groups_structured,
        "formatted": formatted,
        "message": (
            f"Found {len(groups_structured)} group(s) using technique STIX ID "
            f"'{technique_stix_id}' in domain '{domain}'."
        ),
    }

@mcp.tool()
async def get_groups_using_software(
    software_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all APT groups (intrusion sets) that use a specific software/malware.

    This is a reverse lookup: Software → Groups.
    It follows 'uses' relationships from a software STIX ID (tool/malware)
    to intrusion sets.

    Args:
        software_stix_id: STIX ID of the software object
                          (e.g., "malware--UUID", "tool--UUID").
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include group descriptions.

    Returns:
        {
          "software": {
              "attack_id": "SXXXX or similar" | null,
              "name": "<software name or null>",
              "stix_id": "<software STIX ID>",
              "type": "<tool|malware|...> or null",
              "description": "<text or null>",
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
    attack_data = get_attack_data(domain)

    # Optional: resolve software metadata
    try:
        sw_obj = attack_data.get_object_by_stix_id(software_stix_id)
    except Exception:
        sw_obj = None

    software_info: Optional[Dict[str, Any]] = None
    if sw_obj is not None:
        if isinstance(sw_obj, dict):
            s_name = sw_obj.get("name")
            s_type = sw_obj.get("type")
            s_desc = sw_obj.get("description") if include_description else None
        else:
            s_name = getattr(sw_obj, "name", None)
            s_type = getattr(sw_obj, "type", None)
            s_desc = getattr(sw_obj, "description", None) if include_description else None

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
            "software": software_info,
            "count": 0,
            "groups": [],
            "formatted": "",
            "message": (
                f"No groups found using software STIX ID '{software_stix_id}' "
                f"in domain '{domain}'."
            ),
        }

    groups_structured: List[Dict[str, Any]] = []
    group_objects_for_format: List[Any] = []

    for entry in rel_entries:
        # RelationshipEntry-like or plain group object
        if isinstance(entry, dict) and ("object" in entry or "relationships" in entry):
            grp_obj = entry.get("object", entry)
            rels = entry.get("relationships", [])
        else:
            grp_obj = entry
            rels = []

        if grp_obj is None:
            continue

        group_objects_for_format.append(grp_obj)

        if isinstance(grp_obj, dict):
            g_name = grp_obj.get("name")
            g_stix_id = grp_obj.get("id")
            g_aliases = grp_obj.get("aliases", [])
            g_desc = grp_obj.get("description") if include_description else None
        else:
            g_name = getattr(grp_obj, "name", None)
            g_stix_id = getattr(grp_obj, "id", None)
            g_aliases = getattr(grp_obj, "aliases", [])
            g_desc = getattr(grp_obj, "description", None) if include_description else None

        try:
            g_attack_id = attack_data.get_attack_id(g_stix_id)
        except Exception:
            g_attack_id = None

        relationships_info = []
        for r in rels:
            if isinstance(r, dict):
                r_id = r.get("id")
                r_type = r.get("relationship_type")
                r_desc = r.get("description")
                r_source = r.get("source_ref")
                r_target = r.get("target_ref")
            else:
                r_id = getattr(r, "id", None)
                r_type = getattr(r, "relationship_type", None)
                r_desc = getattr(r, "description", None)
                r_source = getattr(r, "source_ref", None)
                r_target = getattr(r, "target_ref", None)

            relationships_info.append(
                {
                    "stix_id": r_id,
                    "relationship_type": r_type,
                    "description": r_desc,
                    "source_ref": r_source,
                    "target_ref": r_target,
                }
            )

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
    if group_objects_for_format:
        formatted = format_objects(
            group_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "software": software_info,
        "count": len(groups_structured),
        "groups": groups_structured,
        "formatted": formatted,
        "message": (
            f"Found {len(groups_structured)} group(s) using software STIX ID "
            f"'{software_stix_id}' in domain '{domain}'."
        ),
    }

@mcp.tool()
async def get_groups_attributing_to_campaign(
    campaign_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all APT groups (intrusion sets) attributed to a specific campaign.

    This is a reverse lookup: Campaign → Groups.
    It follows attribution relationships from a campaign STIX ID to
    intrusion sets (groups).

    Args:
        campaign_stix_id: STIX ID of the campaign (e.g., "campaign--UUID").
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include group descriptions.

    Returns:
        {
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

    # Optional: resolve campaign metadata
    try:
        camp_obj = attack_data.get_object_by_stix_id(campaign_stix_id)
    except Exception:
        camp_obj = None

    campaign_info: Optional[Dict[str, Any]] = None
    if camp_obj is not None:
        if isinstance(camp_obj, dict):
            c_name = camp_obj.get("name")
            c_desc = camp_obj.get("description") if include_description else None
        else:
            c_name = getattr(camp_obj, "name", None)
            c_desc = getattr(camp_obj, "description", None) if include_description else None

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
        # RelationshipEntry-like or plain group object
        if isinstance(entry, dict) and ("object" in entry or "relationships" in entry):
            grp_obj = entry.get("object", entry)
            rels = entry.get("relationships", [])
        else:
            grp_obj = entry
            rels = []

        if grp_obj is None:
            continue

        group_objects_for_format.append(grp_obj)

        # Extract group fields
        if isinstance(grp_obj, dict):
            g_name = grp_obj.get("name")
            g_stix_id = grp_obj.get("id")
            g_aliases = grp_obj.get("aliases", [])
            g_desc = grp_obj.get("description") if include_description else None
        else:
            g_name = getattr(grp_obj, "name", None)
            g_stix_id = getattr(grp_obj, "id", None)
            g_aliases = getattr(grp_obj, "aliases", [])
            g_desc = getattr(grp_obj, "description", None) if include_description else None

        # External ATT&CK ID (GXXXX)
        try:
            g_attack_id = attack_data.get_attack_id(g_stix_id)
        except Exception:
            g_attack_id = None

        relationships_info = []
        for r in rels:
            if isinstance(r, dict):
                r_id = r.get("id")
                r_type = r.get("relationship_type")
                r_desc = r.get("description")
                r_source = r.get("source_ref")
                r_target = r.get("target_ref")
            else:
                r_id = getattr(r, "id", None)
                r_type = getattr(r, "relationship_type", None)
                r_desc = getattr(r, "description", None)
                r_source = getattr(r, "source_ref", None)
                r_target = getattr(r, "target_ref", None)

            relationships_info.append(
                {
                    "stix_id": r_id,
                    "relationship_type": r_type,
                    "description": r_desc,
                    "source_ref": r_source,
                    "target_ref": r_target,
                }
            )

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
    if group_objects_for_format:
        formatted = format_objects(
            group_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
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
@mcp.tool()
async def get_software_by_alias(
    alias: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Find software/malware by alias (e.g., 'Beacon', 'Mimilib').

    Many malware/tools have multiple alternative names. This tool searches
    the software catalog for alias matches.

    Args:
        alias: Alias to search for.
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include description fields.

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

    # Query the underlying library
    try:
        results = attack_data.get_software_by_alias(alias)
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
        # MITRE library returns STIX objects that may be dicts or objects
        if isinstance(sw, dict):
            s_name = sw.get("name")
            s_stix_id = sw.get("id")
            s_aliases = sw.get("aliases", [])
            s_type = sw.get("type")
            s_desc = sw.get("description") if include_description else None
        else:
            s_name = getattr(sw, "name", None)
            s_stix_id = getattr(sw, "id", None)
            s_aliases = getattr(sw, "aliases", [])
            s_type = getattr(sw, "type", None)
            s_desc = getattr(sw, "description", None) if include_description else None

        # External ATT&CK ID (e.g., SXXXX)
        try:
            s_attack_id = attack_data.get_attack_id(s_stix_id)
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
    if software_objects_for_format:
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

@mcp.tool()
async def get_software_using_technique(
    technique_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all software (malware/tools) that use a specific technique.

    This is a reverse lookup: Technique → Software.
    It follows 'uses' relationships from a technique STIX ID to software
    (malware and tools) that implement or leverage that technique.

    Args:
        technique_stix_id: STIX ID of the technique
                           (e.g., "attack-pattern--UUID").
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include software descriptions.

    Returns:
        {
          "technique": {
              "attack_id": "TXXXX or TXXXX.YYY" | null,
              "name": "<technique name or null>",
              "stix_id": "<attack-pattern--UUID>",
              "description": "<text or null>",
          } | null,

          "count": <number of software objects>,

          "software": [
            {
              "attack_id": "SXXXX or similar" | null,
              "name": "<software name>",
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
    attack_data = get_attack_data(domain)

    # Optional: resolve technique metadata for context
    try:
        tech_obj = attack_data.get_object_by_stix_id(technique_stix_id)
    except Exception:
        tech_obj = None

    technique_info: Optional[Dict[str, Any]] = None
    if tech_obj is not None:
        if isinstance(tech_obj, dict):
            t_name = tech_obj.get("name")
            t_desc = tech_obj.get("description") if include_description else None
        else:
            t_name = getattr(tech_obj, "name", None)
            t_desc = getattr(tech_obj, "description", None) if include_description else None

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
            "technique": technique_info,
            "count": 0,
            "software": [],
            "formatted": "",
            "message": (
                f"No software found using technique STIX ID "
                f"'{technique_stix_id}' in domain '{domain}'."
            ),
        }

    software_structured: List[Dict[str, Any]] = []
    software_objects_for_format: List[Any] = []

    for entry in rel_entries:
        # Some helpers may return RelationshipEntry-like objects (with "object"/"relationships"),
        # others may return plain software STIX objects. We need to Handle both.
        if isinstance(entry, dict) and ("object" in entry or "relationships" in entry):
            sw_obj = entry.get("object", entry)
            rels = entry.get("relationships", [])
        else:
            sw_obj = entry
            rels = []

        if sw_obj is None:
            continue

        software_objects_for_format.append(sw_obj)

        # Extract software fields
        if isinstance(sw_obj, dict):
            s_name = sw_obj.get("name")
            s_stix_id = sw_obj.get("id")
            s_type = sw_obj.get("type")
            s_desc = sw_obj.get("description") if include_description else None
        else:
            s_name = getattr(sw_obj, "name", None)
            s_stix_id = getattr(sw_obj, "id", None)
            s_type = getattr(sw_obj, "type", None)
            s_desc = getattr(sw_obj, "description", None) if include_description else None

        # External ATT&CK ID (SXXXX / sometimes other prefix)
        try:
            s_attack_id = attack_data.get_attack_id(s_stix_id)
        except Exception:
            s_attack_id = None

        # Relationship metadata (if present)
        relationships_info = []
        for r in rels:
            if isinstance(r, dict):
                r_id = r.get("id")
                r_type = r.get("relationship_type")
                r_desc = r.get("description")
                r_source = r.get("source_ref")
                r_target = r.get("target_ref")
            else:
                r_id = getattr(r, "id", None)
                r_type = getattr(r, "relationship_type", None)
                r_desc = getattr(r, "description", None)
                r_source = getattr(r, "source_ref", None)
                r_target = getattr(r, "target_ref", None)

            relationships_info.append(
                {
                    "stix_id": r_id,
                    "relationship_type": r_type,
                    "description": r_desc,
                    "source_ref": r_source,
                    "target_ref": r_target,
                }
            )

        software_structured.append(
            {
                "attack_id": s_attack_id,
                "name": s_name,
                "stix_id": s_stix_id,
                "type": s_type,
                "description": s_desc,
                "relationships": relationships_info,
            }
        )

    formatted = ""
    if software_objects_for_format:
        formatted = format_objects(
            software_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "technique": technique_info,
        "count": len(software_structured),
        "software": software_structured,
        "formatted": formatted,
        "message": (
            f"Found {len(software_structured)} software object(s) using "
            f"technique STIX ID '{technique_stix_id}' in domain '{domain}'."
        ),
    }

@mcp.tool()
async def get_techniques_used_by_software(
    software_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all techniques used by specific software/malware.

    This shows what ATT&CK techniques a given software (tool/malware) is
    capable of performing.

    Args:
        software_stix_id: STIX ID of the software object
                          (e.g., "malware--UUID", "tool--UUID").
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include technique descriptions.

    Returns:
        {
          "software": {
              "attack_id": "SXXXX or similar" | null,
              "name": "<software name or null>",
              "stix_id": "<software STIX ID>",
              "type": "<malware|tool|...> or null",
              "description": "<text or null>",
          } | null,

          "count": <number of techniques>,

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
    attack_data = get_attack_data(domain)

    # Optional: resolve software metadata for context
    try:
        sw_obj = attack_data.get_object_by_stix_id(software_stix_id)
    except Exception:
        sw_obj = None

    software_info: Optional[Dict[str, Any]] = None
    if sw_obj is not None:
        if isinstance(sw_obj, dict):
            s_name = sw_obj.get("name")
            s_type = sw_obj.get("type")
            s_desc = sw_obj.get("description") if include_description else None
        else:
            s_name = getattr(sw_obj, "name", None)
            s_type = getattr(sw_obj, "type", None)
            s_desc = getattr(sw_obj, "description", None) if include_description else None

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
            "software": software_info,
            "count": 0,
            "techniques": [],
            "formatted": "",
            "message": (
                f"No techniques found for software STIX ID "
                f"'{software_stix_id}' in domain '{domain}'."
            ),
        }

    techniques_structured: List[Dict[str, Any]] = []
    technique_objects_for_format: List[Any] = []

    for entry in rel_entries:
        # RelationshipEntry-like or plain technique object
        if isinstance(entry, dict) and ("object" in entry or "relationships" in entry):
            tech_obj = entry.get("object", entry)
            rels = entry.get("relationships", [])
        else:
            tech_obj = entry
            rels = []

        if tech_obj is None:
            continue

        technique_objects_for_format.append(tech_obj)

        # Extract technique info
        if isinstance(tech_obj, dict):
            t_name = tech_obj.get("name")
            t_stix_id = tech_obj.get("id")
            t_desc = tech_obj.get("description") if include_description else None
        else:
            t_name = getattr(tech_obj, "name", None)
            t_stix_id = getattr(tech_obj, "id", None)
            t_desc = getattr(tech_obj, "description", None) if include_description else None

        # External ATT&CK ID (TXXXX / TXXXX.YYY)
        try:
            t_attack_id = attack_data.get_attack_id(t_stix_id)
        except Exception:
            t_attack_id = None

        # Relationship metadata
        relationships_info = []
        for r in rels:
            if isinstance(r, dict):
                r_id = r.get("id")
                r_type = r.get("relationship_type")
                r_desc = r.get("description")
                r_source = r.get("source_ref")
                r_target = r.get("target_ref")
            else:
                r_id = getattr(r, "id", None)
                r_type = getattr(r, "relationship_type", None)
                r_desc = getattr(r, "description", None)
                r_source = getattr(r, "source_ref", None)
                r_target = getattr(r, "target_ref", None)

            relationships_info.append(
                {
                    "stix_id": r_id,
                    "relationship_type": r_type,
                    "description": r_desc,
                    "source_ref": r_source,
                    "target_ref": r_target,
                }
            )

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
    if technique_objects_for_format:
        formatted = format_objects(
            technique_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "software": software_info,
        "count": len(techniques_structured),
        "techniques": techniques_structured,
        "formatted": formatted,
        "message": (
            f"Found {len(techniques_structured)} technique(s) used by software "
            f"STIX ID '{software_stix_id}' in domain '{domain}'."
        ),
    }

#####################################################################
    # "Get All" functions for MITRE ATT&CK objects
#####################################################################

@mcp.tool()
async def get_all_techniques(
    domain: str = "enterprise",
    remove_revoked_deprecated: bool = True,
    include_description: bool = False,
) -> Dict[str, Any]:
    """
    Get all ATT&CK techniques for a given domain.

    Args:
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        remove_revoked_deprecated: Whether to exclude revoked/deprecated techniques.
        include_description: Whether to include technique descriptions.

    Returns:
        {
          "domain": "<domain>",
          "count": <number of techniques>,
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

    # Fetch techniques from MITRE library
    try:
        techniques = attack_data.get_techniques(
            remove_revoked_deprecated=remove_revoked_deprecated
        )
    except Exception:
        return {
            "domain": domain,
            "count": 0,
            "techniques": [],
            "formatted": "",
            "message": f"Unable to retrieve techniques for domain '{domain}'."
        }

    if not techniques:
        return {
            "domain": domain,
            "count": 0,
            "techniques": [],
            "formatted": "",
            "message": f"No techniques found in domain '{domain}'."
        }

    structured = []
    technique_objects_for_format = []

    for tech in techniques:
        technique_objects_for_format.append(tech)

        # Extract fields (both dict or object)
        if isinstance(tech, dict):
            name = tech.get("name")
            stix_id = tech.get("id")
            description = tech.get("description") if include_description else None
            phases = tech.get("kill_chain_phases", [])
        else:
            name = getattr(tech, "name", None)
            stix_id = getattr(tech, "id", None)
            description = getattr(tech, "description", None) if include_description else None
            phases = getattr(tech, "kill_chain_phases", [])

        # ATT&CK external ID (TXXXX)
        try:
            attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            attack_id = None

        # Map kill chain phases to readable tactics
        tactics = []
        for p in phases or []:
            phase_name = getattr(p, "phase_name", None) or p.get("phase_name")
            if phase_name:
                tactics.append(phase_name.replace("-", " ").title())

        structured.append(
            {
                "attack_id": attack_id,
                "name": name,
                "stix_id": stix_id,
                "description": description,
                "tactics": tactics,
            }
        )

    # Formatted block (optional)
    formatted = ""
    if technique_objects_for_format:
        formatted = format_objects(
            technique_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "domain": domain,
        "count": len(structured),
        "techniques": structured,
        "formatted": formatted,
        "message": (
            f"Found {len(structured)} technique(s) in domain '{domain}' "
            f"(remove_revoked_deprecated={remove_revoked_deprecated})."
        ),
    }

@mcp.tool()
async def get_all_subtechniques(
    domain: str = "enterprise",
    remove_revoked_deprecated: bool = True,
    include_description: bool = False,
) -> Dict[str, Any]:
    """
    Get all subtechniques in a given ATT&CK domain.

    Subtechniques are more specific versions of parent techniques,
    e.g., T1566.001 and T1566.002 are subtechniques of T1566.

    Args:
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        remove_revoked_deprecated: Whether to exclude revoked/deprecated subtechniques.
        include_description: Whether to include descriptions.

    Returns:
        {
          "domain": "<domain>",
          "count": <number of subtechniques>,
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

    # Get all techniques including subtechniques
    try:
        all_techniques = attack_data.get_techniques(
            remove_revoked_deprecated=remove_revoked_deprecated,
            include_subtechniques=True,
        )
    except Exception:
        return {
            "domain": domain,
            "count": 0,
            "subtechniques": [],
            "formatted": "",
            "message": f"Unable to retrieve techniques for domain '{domain}'.",
        }

    subtechnique_objects: List[Any] = []
    structured: List[Dict[str, Any]] = []

    for t in all_techniques:
        # Determine the STIX ID for this technique
        if isinstance(t, dict):
            stix_id = t.get("id")
            name = t.get("name")
            description = t.get("description") if include_description else None
            phases = t.get("kill_chain_phases", []) or []
        else:
            stix_id = getattr(t, "id", None)
            name = getattr(t, "name", None)
            description = getattr(t, "description", None) if include_description else None
            phases = getattr(t, "kill_chain_phases", []) or []

        if not stix_id:
            continue

        # Check if this technique has a parent (i.e., is a subtechnique)
        try:
            parent_obj = attack_data.get_parent_technique_of_subtechnique(stix_id)
        except Exception:
            parent_obj = None

        if not parent_obj:
            # Not a subtechnique
            continue

        # At this point, t is a subtechnique
        subtechnique_objects.append(t)

        # Resolve subtechnique ATT&CK ID
        try:
            sub_attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            sub_attack_id = None

        # Resolve parent fields
        if isinstance(parent_obj, dict):
            parent_stix_id = parent_obj.get("id")
            parent_name = parent_obj.get("name")
        else:
            parent_stix_id = getattr(parent_obj, "id", None)
            parent_name = getattr(parent_obj, "name", None)

        try:
            parent_attack_id = (
                attack_data.get_attack_id(parent_stix_id) if parent_stix_id else None
            )
        except Exception:
            parent_attack_id = None

        # Extract tactics from kill_chain_phases
        tactics: List[str] = []
        for p in phases:
            if isinstance(p, dict):
                phase_name = p.get("phase_name")
            else:
                phase_name = getattr(p, "phase_name", None)

            if phase_name:
                tactics.append(phase_name.replace("-", " ").title())

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

    if not structured:
        return {
            "domain": domain,
            "count": 0,
            "subtechniques": [],
            "formatted": "",
            "message": (
                f"No subtechniques found in domain '{domain}' "
                f"(remove_revoked_deprecated={remove_revoked_deprecated})."
            ),
        }

    # Optional human-readable formatting using your existing helper
    formatted = format_objects(
        subtechnique_objects,
        include_description=include_description,
        domain=domain,
    )

    return {
        "domain": domain,
        "count": len(structured),
        "subtechniques": structured,
        "formatted": formatted,
        "message": (
            f"Found {len(structured)} subtechnique(s) in domain '{domain}' "
            f"(remove_revoked_deprecated={remove_revoked_deprecated})."
        ),
    }

@mcp.tool()
async def get_all_parent_techniques(
    domain: str = "enterprise",
    remove_revoked_deprecated: bool = True,
    include_description: bool = False,
) -> Dict[str, Any]:
    """
    Get all parent techniques (exclude subtechniques) in a given domain.

    Parent techniques are the main techniques without a dot in their ATT&CK ID,
    e.g., T1566, T1055 (not T1566.001).

    Args:
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        remove_revoked_deprecated: Whether to exclude revoked/deprecated techniques.
        include_description: Whether to include descriptions.

    Returns:
        {
          "domain": "<domain>",
          "count": <number of parent techniques>,
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

    try:
        # This call *already* returns techniques without including subtechniques
        techniques = attack_data.get_techniques(
            remove_revoked_deprecated=remove_revoked_deprecated
        )
    except Exception:
        return {
            "domain": domain,
            "count": 0,
            "parent_techniques": [],
            "formatted": "",
            "message": f"Unable to retrieve techniques for domain '{domain}'.",
        }

    parent_objects: List[Any] = []
    structured: List[Dict[str, Any]] = []

    for t in techniques:
        # Extract STIX ID, name, description, kill chain phases
        if isinstance(t, dict):
            stix_id = t.get("id")
            name = t.get("name")
            description = t.get("description") if include_description else None
            phases = t.get("kill_chain_phases", []) or []
        else:
            stix_id = getattr(t, "id", None)
            name = getattr(t, "name", None)
            description = getattr(t, "description", None) if include_description else None
            phases = getattr(t, "kill_chain_phases", []) or []

        if not stix_id:
            continue

        # Resolve ATT&CK ID
        try:
            attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            attack_id = None

        if not attack_id:
            # If we can't resolve an ATT&CK ID, skip parent-check
            continue

        # Parent techniques: no dot in ATT&CK ID
        if "." in attack_id:
            continue

        parent_objects.append(t)

        # Extract tactics from kill_chain_phases
        tactics: List[str] = []
        for p in phases:
            if isinstance(p, dict):
                phase_name = p.get("phase_name")
            else:
                phase_name = getattr(p, "phase_name", None)

            if phase_name:
                tactics.append(phase_name.replace("-", " ").title())

        structured.append(
            {
                "attack_id": attack_id,
                "name": name,
                "stix_id": stix_id,
                "description": description,
                "tactics": tactics,
            }
        )

    if not structured:
        return {
            "domain": domain,
            "count": 0,
            "parent_techniques": [],
            "formatted": "",
            "message": (
                f"No parent techniques found in domain '{domain}' "
                f"(remove_revoked_deprecated={remove_revoked_deprecated})."
            ),
        }

    formatted = format_objects(
        parent_objects,
        include_description=include_description,
        domain=domain,
    )

    return {
        "domain": domain,
        "count": len(structured),
        "parent_techniques": structured,
        "formatted": formatted,
        "message": (
            f"Found {len(structured)} parent technique(s) in domain '{domain}' "
            f"(remove_revoked_deprecated={remove_revoked_deprecated})."
        ),
    }

@mcp.tool()
async def get_all_groups(
    domain: str = "enterprise",
    remove_revoked_deprecated: bool = True,
    include_description: bool = False,
) -> Dict[str, Any]:
    """
    Get all APT groups (intrusion sets) in a domain.

    Args:
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        remove_revoked_deprecated: Whether to exclude revoked/deprecated groups.
        include_description: Whether to include descriptions.

    Returns:
        {
          "domain": "<domain>",
          "count": <number of groups>,
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

    # Fetch groups
    try:
        groups = attack_data.get_groups(
            remove_revoked_deprecated=remove_revoked_deprecated
        )
    except Exception:
        return {
            "domain": domain,
            "count": 0,
            "groups": [],
            "formatted": "",
            "message": f"Unable to retrieve groups for domain '{domain}'."
        }

    if not groups:
        return {
            "domain": domain,
            "count": 0,
            "groups": [],
            "formatted": "",
            "message": (
                f"No APT groups found in domain '{domain}' "
                f"(remove_revoked_deprecated={remove_revoked_deprecated})."
            )
        }

    structured = []
    groups_for_format = []

    for g in groups:
        groups_for_format.append(g)

        if isinstance(g, dict):
            name = g.get("name")
            stix_id = g.get("id")
            aliases = g.get("aliases", [])
            description = g.get("description") if include_description else None
        else:
            name = getattr(g, "name", None)
            stix_id = getattr(g, "id", None)
            aliases = getattr(g, "aliases", [])
            description = getattr(g, "description", None) if include_description else None

        # External ATT&CK ID (GXXXX)
        try:
            attack_id = attack_data.get_attack_id(stix_id)
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

    # Optional formatted human-readable block
    formatted = format_objects(
        groups_for_format,
        include_description=include_description,
        domain=domain,
    )

    return {
        "domain": domain,
        "count": len(structured),
        "groups": structured,
        "formatted": formatted,
        "message": (
            f"Found {len(structured)} APT group(s) in domain '{domain}' "
            f"(remove_revoked_deprecated={remove_revoked_deprecated})."
        ),
    }

@mcp.tool()
async def get_all_software(
    domain: str = "enterprise",
    remove_revoked_deprecated: bool = True,
    include_description: bool = False,
) -> Dict[str, Any]:
    """
    Get all software (malware and tools) in a domain.

    This is effectively an alias for the MITRE helper get_software(), but it
    returns structured results suitable for LLMs and clients.

    Args:
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        remove_revoked_deprecated: Whether to exclude revoked/deprecated software.
        include_description: Whether to include descriptions.

    Returns:
        {
          "domain": "<domain>",
          "count": <number of software objects>,
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

    # Fetch software objects from the MITRE library
    try:
        software_items = attack_data.get_software(
            remove_revoked_deprecated=remove_revoked_deprecated
        )
    except Exception:
        return {
            "domain": domain,
            "count": 0,
            "software": [],
            "formatted": "",
            "message": f"Unable to retrieve software for domain '{domain}'.",
        }

    if not software_items:
        return {
            "domain": domain,
            "count": 0,
            "software": [],
            "formatted": "",
            "message": (
                f"No software found in domain '{domain}' "
                f"(remove_revoked_deprecated={remove_revoked_deprecated})."
            ),
        }

    structured: List[Dict[str, Any]] = []
    software_for_format: List[Any] = []

    for sw in software_items:
        software_for_format.append(sw)

        if isinstance(sw, dict):
            name = sw.get("name")
            stix_id = sw.get("id")
            aliases = sw.get("aliases", [])
            sw_type = sw.get("type")
            description = sw.get("description") if include_description else None
        else:
            name = getattr(sw, "name", None)
            stix_id = getattr(sw, "id", None)
            aliases = getattr(sw, "aliases", [])
            sw_type = getattr(sw, "type", None)
            description = getattr(sw, "description", None) if include_description else None

        # External ATT&CK ID (often SXXXX)
        try:
            attack_id = attack_data.get_attack_id(stix_id)
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

    # Optional human-readable formatted view
    formatted = format_objects(
        software_for_format,
        include_description=include_description,
        domain=domain,
    )

    return {
        "domain": domain,
        "count": len(structured),
        "software": structured,
        "formatted": formatted,
        "message": (
            f"Found {len(structured)} software object(s) in domain '{domain}' "
            f"(remove_revoked_deprecated={remove_revoked_deprecated})."
        ),
    }

@mcp.tool()
async def get_all_mitigations(
    domain: str = "enterprise",
    remove_revoked_deprecated: bool = True,
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all mitigations (defensive countermeasures) in a domain.

    Mitigations are security controls or practices that can reduce the
    effectiveness of adversary techniques (e.g., M1013, M1017).

    Args:
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        remove_revoked_deprecated: Whether to exclude revoked/deprecated mitigations.
        include_description: Whether to include descriptions.

    Returns:
        {
          "domain": "<domain>",
          "count": <number of mitigations>,
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

    # Fetch mitigations from MITRE library
    try:
        mitigations = attack_data.get_mitigations(
            remove_revoked_deprecated=remove_revoked_deprecated
        )
    except Exception:
        return {
            "domain": domain,
            "count": 0,
            "mitigations": [],
            "formatted": "",
            "message": f"Unable to retrieve mitigations for domain '{domain}'.",
        }

    if not mitigations:
        return {
            "domain": domain,
            "count": 0,
            "mitigations": [],
            "formatted": "",
            "message": (
                f"No mitigations found in domain '{domain}' "
                f"(remove_revoked_deprecated={remove_revoked_deprecated})."
            ),
        }

    structured: List[Dict[str, Any]] = []
    mitigations_for_format: List[Any] = []

    for m in mitigations:
        mitigations_for_format.append(m)

        if isinstance(m, dict):
            name = m.get("name")
            stix_id = m.get("id")
            description = m.get("description") if include_description else None
        else:
            name = getattr(m, "name", None)
            stix_id = getattr(m, "id", None)
            description = getattr(m, "description", None) if include_description else None

        # External ATT&CK ID (MXXXX)
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
        mitigations_for_format,
        include_description=include_description,
        domain=domain,
    )

    return {
        "domain": domain,
        "count": len(structured),
        "mitigations": structured,
        "formatted": formatted,
        "message": (
            f"Found {len(structured)} mitigation(s) in domain '{domain}' "
            f"(remove_revoked_deprecated={remove_revoked_deprecated})."
        ),
    }

@mcp.tool()
async def get_all_tactics(
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all ATT&CK tactics for a domain.

    Tactics represent the adversary's tactical goals (e.g., Initial Access,
    Defense Evasion, Persistence).

    Args:
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics')
        include_description: Whether to include tactic descriptions.

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
    formatted = format_objects(
        tactics_for_format,
        include_description=include_description,
        domain=domain,
    )

    return {
        "domain": domain,
        "count": len(structured),
        "tactics": structured,
        "formatted": formatted,
        "message": f"Found {len(structured)} tactic(s) in domain '{domain}'.",
    }


@mcp.tool()
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

@mcp.tool()
async def get_all_campaigns(
    domain: str = "enterprise",
    remove_revoked_deprecated: bool = True,
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all ATT&CK campaigns in a domain.

    Campaigns represent specific intrusion events or long-running operations 
    attributed to threat actors (e.g., SolarWinds, Operation Ghost).

    Args:
        domain: ATT&CK domain ("enterprise", "mobile", "ics")
        remove_revoked_deprecated: Whether to exclude revoked/deprecated entries
        include_description: Include campaign descriptions in the output

    Returns:
        {
          "domain": "<domain>",
          "count": <int>,
          "campaigns": [
             {
                "attack_id": "<Cxxxx or None>",
                "name": "<campaign name>",
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

    # Fetch from MITRE data
    try:
        campaigns = attack_data.get_campaigns(
            remove_revoked_deprecated=remove_revoked_deprecated
        )
    except Exception:
        return {
            "domain": domain,
            "count": 0,
            "campaigns": [],
            "formatted": "",
            "message": f"Unable to retrieve campaigns for domain '{domain}'.",
        }

    if not campaigns:
        return {
            "domain": domain,
            "count": 0,
            "campaigns": [],
            "formatted": "",
            "message": (
                f"No campaigns found in domain '{domain}' "
                f"(remove_revoked_deprecated={remove_revoked_deprecated})."
            ),
        }

    structured: List[Dict[str, Any]] = []
    campaigns_for_format: List[Any] = []

    for c in campaigns:
        campaigns_for_format.append(c)

        # Extract fields safely
        if isinstance(c, dict):
            name = c.get("name")
            stix_id = c.get("id")
            description = c.get("description") if include_description else None
        else:
            name = getattr(c, "name", None)
            stix_id = getattr(c, "id", None)
            description = getattr(c, "description", None) if include_description else None

        # Lookup ATT&CK ID (sometimes campaigns do have Cxxxx IDs)
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

    # Human-readable formatted block
    formatted = format_objects(
        campaigns_for_format,
        include_description=include_description,
        domain=domain,
    )

    return {
        "domain": domain,
        "count": len(structured),
        "campaigns": structured,
        "formatted": formatted,
        "message": (
            f"Found {len(structured)} campaign(s) in domain '{domain}' "
            f"(remove_revoked_deprecated={remove_revoked_deprecated})."
        ),
    }

@mcp.tool()
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
        return {
            "domain": domain,
            "count": 0,
            "datasources": [],
            "formatted": "",
            "message": (
                f"No data sources found in domain '{domain}' "
                f"(remove_revoked_deprecated={remove_revoked_deprecated})."
            ),
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

@mcp.tool()
async def get_all_datacomponents(
    domain: str = "enterprise",
    remove_revoked_deprecated: bool = True,
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all ATT&CK data components in a domain.

    Data components are specific aspects of a data source that can be monitored.
    For example, the "Process" data source has components like
    "Process Creation", "Process Termination", etc.

    Args:
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        remove_revoked_deprecated: Whether to exclude revoked/deprecated entries.
        include_description: Whether to include descriptions.

    Returns:
        {
          "domain": "<domain>",
          "count": <number of data components>,
          "datacomponents": [
            {
              "name": "<data component name>",
              "stix_id": "<x-mitre-data-component--UUID>",
              "description": "<text or null>",
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

    # Fetch data components
    try:
        datacomponents = attack_data.get_datacomponents(
            remove_revoked_deprecated=remove_revoked_deprecated
        )
    except Exception:
        return {
            "domain": domain,
            "count": 0,
            "datacomponents": [],
            "formatted": "",
            "message": f"Unable to retrieve data components for domain '{domain}'.",
        }

    if not datacomponents:
        return {
            "domain": domain,
            "count": 0,
            "datacomponents": [],
            "formatted": "",
            "message": (
                f"No data components found in domain '{domain}' "
                f"(remove_revoked_deprecated={remove_revoked_deprecated})."
            ),
        }

    structured: List[Dict[str, Any]] = []
    dc_for_format: List[Any] = []

    for dc in datacomponents:
        dc_for_format.append(dc)

        if isinstance(dc, dict):
            name = dc.get("name")
            stix_id = dc.get("id")
            description = dc.get("description") if include_description else None
            ds_ref = dc.get("x_mitre_data_source_ref") or dc.get("x-mitre-data-source-ref")
        else:
            name = getattr(dc, "name", None)
            stix_id = getattr(dc, "id", None)
            description = getattr(dc, "description", None) if include_description else None
            ds_ref = getattr(dc, "x_mitre_data_source_ref", None)

        # Resolve parent data source (if present)
        data_source_name = None
        data_source_attack_id = None
        data_source_stix_id = ds_ref

        if ds_ref:
            try:
                ds_obj = attack_data.get_object_by_stix_id(ds_ref)
            except Exception:
                ds_obj = None

            if ds_obj is not None:
                if isinstance(ds_obj, dict):
                    data_source_name = ds_obj.get("name")
                    ds_id_for_attack = ds_obj.get("id")
                else:
                    data_source_name = getattr(ds_obj, "name", None)
                    ds_id_for_attack = getattr(ds_obj, "id", None)

                try:
                    data_source_attack_id = attack_data.get_attack_id(ds_id_for_attack)
                except Exception:
                    data_source_attack_id = None

        try:
            dc_attack_id = attack_data.get_attack_id(stix_id) if stix_id else None
        except Exception:
            dc_attack_id = None

        structured.append(
            {
                "attack_id": dc_attack_id,
                "name": name,
                "stix_id": stix_id,
                "description": description,
                "data_source_stix_id": data_source_stix_id,
                "data_source_name": data_source_name,
                "data_source_attack_id": data_source_attack_id,
            }
        )

    # Optional human-readable formatting
    formatted = format_objects(
        dc_for_format,
        include_description=include_description,
        domain=domain,
    )

    return {
        "domain": domain,
        "count": len(structured),
        "datacomponents": structured,
        "formatted": formatted,
        "message": (
            f"Found {len(structured)} data component(s) in domain '{domain}' "
            f"(remove_revoked_deprecated={remove_revoked_deprecated})."
        ),
    }


# ---------------------------------------------------------------------------
# Technique → ICS Assets targeted (ICS domain only)
# ---------------------------------------------------------------------------

@mcp.tool()
async def get_all_assets(
    domain: str = "ics",
    remove_revoked_deprecated: bool = True,
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all ATT&CK assets in a domain (primarily ICS).

    Assets represent industrial control system components 
    (PLC, HMI, Engineering Workstation, Control Server, etc.)

    Args:
        domain: ATT&CK domain ("ics" recommended)
        remove_revoked_deprecated: Exclude revoked/deprecated entries
        include_description: Include asset descriptions

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
          "formatted": "<human-readable output>",
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
    formatted = format_objects(
        assets_for_format,
        include_description=include_description,
        domain=domain,
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

@mcp.tool()
async def get_assets_targeted_by_technique(
    technique_stix_id: str,
    domain: str = "ics",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all ICS assets targeted by a specific technique.

    Assets represent industrial control system components such as
    PLCs, RTUs, Engineering Workstations, HMIs, Control Servers, etc.

    Args:
        technique_stix_id: Technique STIX UUID identifier
        domain: ATT&CK domain ('ics' strongly recommended)
        include_description: Include asset descriptions, if available

    Returns:
        {
          "technique": {
              "attack_id": "Txxxx",
              "name": "...",
              "stix_id": "<attack-pattern--UUID>"
          },
          "count": int,
          "assets": [
            {
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

    # --- Resolve technique metadata ---
    try:
        tech_obj = attack_data.get_object_by_stix_id(technique_stix_id)
    except Exception:
        tech_obj = None

    if tech_obj is not None:
        t_name = getattr(tech_obj, "name", None)
        try:
            t_attack_id = attack_data.get_attack_id(technique_stix_id)
        except Exception:
            t_attack_id = None
    else:
        t_name = None
        try:
            t_attack_id = attack_data.get_attack_id(technique_stix_id)
        except Exception:
            t_attack_id = None

    technique_info = {
        "attack_id": t_attack_id,
        "name": t_name,
        "stix_id": technique_stix_id,
    }

    # --- Fetch assets targeted by this technique ---
    try:
        assets = attack_data.get_assets_targeted_by_technique(
            technique_stix_id
        ) or []
    except Exception:
        assets = []

    if not assets:
        return {
            "technique": technique_info,
            "count": 0,
            "assets": [],
            "formatted": "",
            "message": (
                f"No ICS assets found that are targeted by technique '{t_attack_id}' "
                f"in domain '{domain}'."
            ),
        }

    # --- Build the structured list of assets ---
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

    # --- Human-readable formatting ---
    formatted = format_objects(
        unwrapped_assets,
        include_description=include_description,
        domain=domain,
    )

    return {
        "technique": technique_info,
        "count": len(asset_entries),
        "assets": asset_entries,
        "formatted": formatted,
        "message": (
            f"Found {len(asset_entries)} ICS asset(s) targeted by technique "
            f"'{t_attack_id}' ({t_name}) in domain '{domain}'."
        ),
    }

@mcp.tool()
async def get_techniques_targeting_asset(
    asset_stix_id: str,
    domain: str = "ics",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all techniques that target a specific ICS asset.

    Shows which adversary techniques can affect a given industrial
    control system component.

    Args:
        asset_stix_id: STIX ID of the ICS asset
        domain: Domain (default: 'ics')
        include_description: Whether to include descriptions in formatted output

    Returns:
        {
            "found": bool,
            "count": int,
            "techniques": [
                {
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

    try:
        techniques = attack_data.get_techniques_targeting_asset(asset_stix_id) or []
    except Exception as e:
        return {
            "found": False,
            "count": 0,
            "techniques": [],
            "formatted": "",
            "message": f"Error retrieving techniques: {e}",
        }

    if not techniques:
        return {
            "found": False,
            "count": 0,
            "techniques": [],
            "formatted": "",
            "message": f"No techniques found targeting asset '{asset_stix_id}' in domain '{domain}'.",
        }

    # Build machine-readable list
    out = []
    unwrapped_techniques = []
    for item in techniques:
        tech = _unwrap_stix_object(item)
        if tech is None:
            continue
        unwrapped_techniques.append(tech)
        stix_id = _stix_get(tech, "id")
        try:
            attack_id = attack_data.get_attack_id(stix_id) if stix_id else None
        except Exception:
            attack_id = None
        out.append(
            {
                "id": attack_id,
                "name": _stix_get(tech, "name"),
                "stix_id": stix_id,
                "description": _stix_get(tech, "description") if include_description else None,
            }
        )

    # Human-readable formatted block
    formatted = format_objects(unwrapped_techniques, include_description=include_description, domain=domain)

    return {
        "found": True,
        "count": len(out),
        "techniques": out,
        "formatted": formatted,
        "message": f"Found {len(out)} techniques targeting asset '{asset_stix_id}'.",
    }

 #####################################################################
    # Campaign functions
#####################################################################

@mcp.tool()
async def get_campaigns_using_technique(
    technique_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all campaigns that use a specific technique.

    This is a reverse lookup: Technique → Campaigns.

    Args:
        technique_stix_id: Technique STIX UUID identifier
                           (e.g., 'attack-pattern--UUID').
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Whether to include campaign descriptions.

    Returns:
        {
          "technique": {
              "attack_id": "TXXXX or TXXXX.YYY" | null,
              "name": "<technique name or null>",
              "stix_id": "<attack-pattern--UUID>",
              "description": "<text or null>",
          } | null,

          "count": <number of campaigns>,

          "campaigns": [
            {
              "attack_id": "CXXXX" | null,
              "name": "<campaign name>",
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
    attack_data = get_attack_data(domain)

    # Optional: resolve technique metadata for context
    try:
        tech_obj = attack_data.get_object_by_stix_id(technique_stix_id)
    except Exception:
        tech_obj = None

    technique_info: Optional[Dict[str, Any]] = None
    if tech_obj is not None:
        if isinstance(tech_obj, dict):
            t_name = tech_obj.get("name")
            t_desc = tech_obj.get("description") if include_description else None
        else:
            t_name = getattr(tech_obj, "name", None)
            t_desc = getattr(tech_obj, "description", None) if include_description else None

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

    # Call MITRE library helper: campaigns using this technique
    try:
        rel_entries = attack_data.get_campaigns_using_technique(technique_stix_id)
    except Exception:
        rel_entries = []

    if not rel_entries:
        return {
            "technique": technique_info,
            "count": 0,
            "campaigns": [],
            "formatted": "",
            "message": (
                f"No campaigns found using technique STIX ID "
                f"'{technique_stix_id}' in domain '{domain}'."
            ),
        }

    campaigns_structured: List[Dict[str, Any]] = []
    campaign_objects_for_format: List[Any] = []

    for entry in rel_entries:
        # Many mitreattack helpers return RelationshipEntry-like dicts:
        # { "object": <campaign>, "relationships": [<relationship>, ...] }
        if isinstance(entry, dict) and ("object" in entry or "relationships" in entry):
            camp_obj = entry.get("object", entry)
            rels = entry.get("relationships", [])
        else:
            camp_obj = entry
            rels = []

        if camp_obj is None:
            continue

        campaign_objects_for_format.append(camp_obj)

        # Extract campaign fields
        if isinstance(camp_obj, dict):
            c_name = camp_obj.get("name")
            c_stix_id = camp_obj.get("id")
            c_desc = camp_obj.get("description") if include_description else None
        else:
            c_name = getattr(camp_obj, "name", None)
            c_stix_id = getattr(camp_obj, "id", None)
            c_desc = getattr(camp_obj, "description", None) if include_description else None

        # External ATT&CK campaign ID (CXXXX)
        try:
            c_attack_id = attack_data.get_attack_id(c_stix_id)
        except Exception:
            c_attack_id = None

        # Relationship metadata (if available)
        relationships_info = []
        for r in rels:
            if isinstance(r, dict):
                r_id = r.get("id")
                r_type = r.get("relationship_type")
                r_desc = r.get("description")
                r_source = r.get("source_ref")
                r_target = r.get("target_ref")
            else:
                r_id = getattr(r, "id", None)
                r_type = getattr(r, "relationship_type", None)
                r_desc = getattr(r, "description", None)
                r_source = getattr(r, "source_ref", None)
                r_target = getattr(r, "target_ref", None)

            relationships_info.append(
                {
                    "stix_id": r_id,
                    "relationship_type": r_type,
                    "description": r_desc,
                    "source_ref": r_source,
                    "target_ref": r_target,
                }
            )

        campaigns_structured.append(
            {
                "attack_id": c_attack_id,
                "name": c_name,
                "stix_id": c_stix_id,
                "description": c_desc,
                "relationships": relationships_info,
            }
        )

    # Optional human-readable formatted output
    formatted = ""
    if campaign_objects_for_format:
        formatted = format_objects(
            campaign_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "technique": technique_info,
        "count": len(campaigns_structured),
        "campaigns": campaigns_structured,
        "formatted": formatted,
        "message": (
            f"Found {len(campaigns_structured)} campaign(s) using technique "
            f"STIX ID '{technique_stix_id}' in domain '{domain}'."
        ),
    }

@mcp.tool()
async def get_techniques_used_by_campaign(
    campaign_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all techniques used in a specific campaign.

    Args:
        campaign_stix_id: Campaign STIX UUID identifier
                          (e.g., 'campaign--UUID').
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Whether to include technique descriptions.

    Returns:
        {
          "campaign": {
              "attack_id": "CXXXX" | null,
              "name": "<campaign name or null>",
              "stix_id": "<campaign--UUID>",
              "description": "<text or null>",
          } | null,

          "count": <number of techniques>,

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

    # Optional: resolve campaign metadata
    try:
        camp_obj = attack_data.get_object_by_stix_id(campaign_stix_id)
    except Exception:
        camp_obj = None

    campaign_info: Optional[Dict[str, Any]] = None
    if camp_obj is not None:
        if isinstance(camp_obj, dict):
            c_name = camp_obj.get("name")
            c_desc = camp_obj.get("description") if include_description else None
        else:
            c_name = getattr(camp_obj, "name", None)
            c_desc = getattr(camp_obj, "description", None) if include_description else None

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

    # Call MITRE helper: techniques used by this campaign
    try:
        rel_entries = attack_data.get_techniques_used_by_campaign(campaign_stix_id)
    except Exception:
        rel_entries = []

    if not rel_entries:
        return {
            "campaign": campaign_info,
            "count": 0,
            "techniques": [],
            "formatted": "",
            "message": (
                f"No techniques found for campaign STIX ID "
                f"'{campaign_stix_id}' in domain '{domain}'."
            ),
        }

    techniques_structured: List[Dict[str, Any]] = []
    technique_objects_for_format: List[Any] = []

    for entry in rel_entries:
        # RelationshipEntry-style: {"object": <technique>, "relationships": [...]}
        if isinstance(entry, dict) and ("object" in entry or "relationships" in entry):
            tech_obj = entry.get("object", entry)
            rels = entry.get("relationships", [])
        else:
            tech_obj = entry
            rels = []

        if tech_obj is None:
            continue

        technique_objects_for_format.append(tech_obj)

        # Extract technique fields
        if isinstance(tech_obj, dict):
            t_name = tech_obj.get("name")
            t_stix_id = tech_obj.get("id")
            t_desc = tech_obj.get("description") if include_description else None
            phases = tech_obj.get("kill_chain_phases", []) or []
        else:
            t_name = getattr(tech_obj, "name", None)
            t_stix_id = getattr(tech_obj, "id", None)
            t_desc = getattr(tech_obj, "description", None) if include_description else None
            phases = getattr(tech_obj, "kill_chain_phases", []) or []

        # ATT&CK technique ID
        try:
            t_attack_id = attack_data.get_attack_id(t_stix_id)
        except Exception:
            t_attack_id = None

        # Tactics from kill_chain_phases
        tactics: List[str] = []
        for p in phases:
            if isinstance(p, dict):
                phase_name = p.get("phase_name")
            else:
                phase_name = getattr(p, "phase_name", None)
            if phase_name:
                tactics.append(phase_name.replace("-", " ").title())

        # Relationship metadata
        relationships_info = []
        for r in rels:
            if isinstance(r, dict):
                r_id = r.get("id")
                r_type = r.get("relationship_type")
                r_desc = r.get("description")
                r_source = r.get("source_ref")
                r_target = r.get("target_ref")
            else:
                r_id = getattr(r, "id", None)
                r_type = getattr(r, "relationship_type", None)
                r_desc = getattr(r, "description", None)
                r_source = getattr(r, "source_ref", None)
                r_target = getattr(r, "target_ref", None)

            relationships_info.append(
                {
                    "stix_id": r_id,
                    "relationship_type": r_type,
                    "description": r_desc,
                    "source_ref": r_source,
                    "target_ref": r_target,
                }
            )

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

    # Optional human-readable formatted block
    formatted = ""
    if technique_objects_for_format:
        formatted = format_objects(
            technique_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "campaign": campaign_info,
        "count": len(techniques_structured),
        "techniques": techniques_structured,
        "formatted": formatted,
        "message": (
            f"Found {len(techniques_structured)} technique(s) used by campaign "
            f"STIX ID '{campaign_stix_id}' in domain '{domain}'."
        ),
    }

@mcp.tool()
async def get_campaigns_using_software(
    software_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all campaigns that use specific software/malware.

    This is a reverse lookup: Software → Campaigns.

    Args:
        software_stix_id: Software STIX UUID identifier (e.g., 'malware--UUID', 'tool--UUID').
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Whether to include campaign descriptions.

    Returns:
        {
          "software": {
              "attack_id": "SXXXX or similar" | null,
              "name": "<software name or null>",
              "stix_id": "<software STIX ID>",
              "type": "<malware|tool|...> or null",
              "description": "<text or null>",
          } | null,

          "count": <number of campaigns>,

          "campaigns": [
            {
              "attack_id": "CXXXX" | null,
              "name": "<campaign name>",
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
    attack_data = get_attack_data(domain)

    # Optional: resolve software metadata for context
    try:
        sw_obj = attack_data.get_object_by_stix_id(software_stix_id)
    except Exception:
        sw_obj = None

    software_info = None
    if sw_obj is not None:
        if isinstance(sw_obj, dict):
            s_name = sw_obj.get("name")
            s_type = sw_obj.get("type")
            s_desc = sw_obj.get("description") if include_description else None
        else:
            s_name = getattr(sw_obj, "name", None)
            s_type = getattr(sw_obj, "type", None)
            s_desc = getattr(sw_obj, "description", None) if include_description else None

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

    # Call MITRE helper: campaigns using this software
    try:
        rel_entries = attack_data.get_campaigns_using_software(software_stix_id)
    except Exception:
        rel_entries = []

    if not rel_entries:
        return {
            "software": software_info,
            "count": 0,
            "campaigns": [],
            "formatted": "",
            "message": (
                f"No campaigns found using software STIX ID "
                f"'{software_stix_id}' in domain '{domain}'."
            ),
        }

    campaigns_structured: List[Dict[str, Any]] = []
    campaign_objects_for_format: List[Any] = []

    for entry in rel_entries:
        # RelationshipEntry-style: {"object": <campaign>, "relationships": [...]}
        if isinstance(entry, dict) and ("object" in entry or "relationships" in entry):
            camp_obj = entry.get("object", entry)
            rels = entry.get("relationships", [])
        else:
            camp_obj = entry
            rels = []

        if camp_obj is None:
            continue

        campaign_objects_for_format.append(camp_obj)

        # Extract campaign fields
        if isinstance(camp_obj, dict):
            c_name = camp_obj.get("name")
            c_stix_id = camp_obj.get("id")
            c_desc = camp_obj.get("description") if include_description else None
        else:
            c_name = getattr(camp_obj, "name", None)
            c_stix_id = getattr(camp_obj, "id", None)
            c_desc = getattr(camp_obj, "description", None) if include_description else None

        # External ATT&CK campaign ID (CXXXX)
        try:
            c_attack_id = attack_data.get_attack_id(c_stix_id)
        except Exception:
            c_attack_id = None

        # Relationship metadata
        relationships_info = []
        for r in rels:
            if isinstance(r, dict):
                r_id = r.get("id")
                r_type = r.get("relationship_type")
                r_desc = r.get("description")
                r_source = r.get("source_ref")
                r_target = r.get("target_ref")
            else:
                r_id = getattr(r, "id", None)
                r_type = getattr(r, "relationship_type", None)
                r_desc = getattr(r, "description", None)
                r_source = getattr(r, "source_ref", None)
                r_target = getattr(r, "target_ref", None)

            relationships_info.append(
                {
                    "stix_id": r_id,
                    "relationship_type": r_type,
                    "description": r_desc,
                    "source_ref": r_source,
                    "target_ref": r_target,
                }
            )

        campaigns_structured.append(
            {
                "attack_id": c_attack_id,
                "name": c_name,
                "stix_id": c_stix_id,
                "description": c_desc,
                "relationships": relationships_info,
            }
        )

    # Optional human-readable formatted output
    formatted = ""
    if campaign_objects_for_format:
        formatted = format_objects(
            campaign_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "software": software_info,
        "count": len(campaigns_structured),
        "campaigns": campaigns_structured,
        "formatted": formatted,
        "message": (
            f"Found {len(campaigns_structured)} campaign(s) using software "
            f"STIX ID '{software_stix_id}' in domain '{domain}'."
        ),
    }

@mcp.tool()
async def get_software_used_by_campaign(
    campaign_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all software/malware used in a specific campaign.

    Args:
        campaign_stix_id: Campaign STIX UUID identifier (e.g., 'campaign--UUID').
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Whether to include software descriptions.

    Returns:
        {
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

    # Resolve campaign metadata for context
    try:
        camp_obj = attack_data.get_object_by_stix_id(campaign_stix_id)
    except Exception:
        camp_obj = None

    campaign_info = None
    if camp_obj is not None:
        if isinstance(camp_obj, dict):
            c_name = camp_obj.get("name")
            c_desc = camp_obj.get("description") if include_description else None
        else:
            c_name = getattr(camp_obj, "name", None)
            c_desc = getattr(camp_obj, "description", None) if include_description else None

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

    # Call MITRE helper: software used by this campaign
    try:
        rel_entries = attack_data.get_software_used_by_campaign(campaign_stix_id)
    except Exception:
        rel_entries = []

    if not rel_entries:
        return {
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
        # Expected: {"object": <software>, "relationships": [...]}
        if isinstance(entry, dict) and ("object" in entry or "relationships" in entry):
            sw_obj = entry.get("object", entry)
            rels = entry.get("relationships", [])
        else:
            sw_obj = entry
            rels = []

        if sw_obj is None:
            continue

        software_objects_for_format.append(sw_obj)

        # Extract software fields
        if isinstance(sw_obj, dict):
            s_name = sw_obj.get("name")
            s_stix_id = sw_obj.get("id")
            s_type = sw_obj.get("type")
            s_aliases = sw_obj.get("aliases", [])
            s_desc = sw_obj.get("description") if include_description else None
        else:
            s_name = getattr(sw_obj, "name", None)
            s_stix_id = getattr(sw_obj, "id", None)
            s_type = getattr(sw_obj, "type", None)
            s_aliases = getattr(sw_obj, "aliases", [])
            s_desc = getattr(sw_obj, "description", None) if include_description else None

        # External ATT&CK software ID (often SXXXX)
        try:
            s_attack_id = attack_data.get_attack_id(s_stix_id)
        except Exception:
            s_attack_id = None

        # Relationship metadata
        relationships_info = []
        for r in rels:
            if isinstance(r, dict):
                r_id = r.get("id")
                r_type = r.get("relationship_type")
                r_desc = r.get("description")
                r_source = r.get("source_ref")
                r_target = r.get("target_ref")
            else:
                r_id = getattr(r, "id", None)
                r_type = getattr(r, "relationship_type", None)
                r_desc = getattr(r, "description", None)
                r_source = getattr(r, "source_ref", None)
                r_target = getattr(r, "target_ref", None)

            relationships_info.append(
                {
                    "stix_id": r_id,
                    "relationship_type": r_type,
                    "description": r_desc,
                    "source_ref": r_source,
                    "target_ref": r_target,
                }
            )

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

    # Optional human-readable formatted output
    formatted = ""
    if software_objects_for_format:
        formatted = format_objects(
            software_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
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

@mcp.tool()
async def get_techniques_by_platform(
    platform: str,
    domain: str = "enterprise",
    include_description: bool = True,
    remove_revoked_deprecated: bool = True,
) -> Dict[str, Any]:
    """
    Get all ATT&CK techniques that apply to a specific platform.

    Args:
        platform: Platform name (e.g., 'Windows', 'Linux', 'macOS', 
                  'Cloud', 'Azure AD', 'Network', etc.)
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
    }
    raw_plat = (platform or "").strip()
    plat_norm = platform_aliases.get(raw_plat.lower(), raw_plat)

    # Resolve canonical platform casing from loaded techniques
    canonical_platform = plat_norm
    try:
        all_techs = attack_data.get_techniques(remove_revoked_deprecated=remove_revoked_deprecated) or []
        known_platforms = {}
        for t in all_techs:
            for p in (_stix_get(t, "x_mitre_platforms", []) or []):
                known_platforms[p.lower()] = p
        if plat_norm.lower() in known_platforms:
            canonical_platform = known_platforms[plat_norm.lower()]
    except Exception:
        pass

    try:
        techniques = attack_data.get_techniques_by_platform(
            canonical_platform,
            remove_revoked_deprecated=remove_revoked_deprecated,
        ) or []
    except TypeError:
        try:
            techniques = attack_data.get_techniques_by_platform(canonical_platform) or []
        except Exception:
            techniques = []
        if remove_revoked_deprecated:
            techniques = [
                t for t in techniques
                if not _stix_get(t, "revoked", False) and not _stix_get(t, "x_mitre_deprecated", False)
            ]
    except Exception:
        techniques = []

    if not techniques:
        return {
            "platform": platform,
            "count": 0,
            "techniques": [],
            "formatted": "",
            "message": (
                f"No techniques found for platform '{platform}' "
                f"in domain '{domain}'."
            ),
        }

    structured = []
    for tech in techniques:
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
    formatted = format_objects(
        techniques,
        include_description=include_description,
        domain=domain,
    )

    return {
        "platform": platform,
        "count": len(structured),
        "techniques": structured,
        "formatted": formatted,
        "message": (
            f"Found {len(structured)} technique(s) applicable to platform "
            f"'{platform}' in domain '{domain}'."
        ),
    }

@mcp.tool()
async def get_parent_technique_of_subtechnique(
    technique_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get the parent technique of a subtechnique.

    Args:
        technique_stix_id: STIX UUID of the subtechnique.
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Whether to include the parent's description.

    Returns:
        {
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

    # First: resolve ATT&CK ID of the subtechnique
    try:
        sub_attack_id = attack_data.get_attack_id(technique_stix_id)
    except Exception:
        sub_attack_id = None

    # Try retrieving the parent entry / STIX ID
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
            "subtechnique_stix_id": technique_stix_id,
            "subtechnique_attack_id": sub_attack_id,
            "parent": None,
            "formatted": "",
            "message": (
                f"No parent technique found — '{technique_stix_id}' "
                f"is not a subtechnique in domain '{domain}'."
            ),
        }

    # Extract parent attributes
    parent_name = _stix_get(parent_obj, "name")
    parent_desc = _stix_get(parent_obj, "description") if include_description else None

    try:
        parent_attack_id = attack_data.get_attack_id(parent_stix_id)
    except Exception:
        parent_attack_id = None

    # Human-readable formatting
    formatted = format_objects(
        [parent_obj],
        include_description=include_description,
        domain=domain,
    )

    return {
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

@mcp.tool()
async def get_subtechniques_of_technique(
    technique_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = False,
) -> Dict[str, Any]:
    """
    Get all subtechniques of a parent technique.

    Args:
        technique_stix_id: STIX UUID of the parent technique.
        domain: ATT&CK domain.
        include_description: Whether to include subtechnique descriptions.

    Returns:
        {
          "parent": {
              "stix_id": "...",
              "attack_id": "...",
              "name": "..."
          },
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

    # Resolve parent attributes
    try:
        parent_attack_id = attack_data.get_attack_id(technique_stix_id)
    except Exception:
        parent_attack_id = None

    parent_obj = attack_data.get_object_by_stix_id(technique_stix_id)
    parent_name = getattr(parent_obj, "name", None) if parent_obj else None

    # Retrieve subtechniques
    try:
        subs = attack_data.get_subtechniques_of_technique(technique_stix_id) or []
    except Exception:
        subs = []

    if not subs:
        return {
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

    # Convert subtechniques to structured form
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

    # Human-readable formatting
    formatted = format_objects(
        unwrapped_subs,
        include_description=include_description,
        domain=domain,
    )

    return {
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

@mcp.tool()
async def get_techniques_mitigated_by_mitigation(
    mitigation_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = False,
) -> Dict[str, Any]:
    """
    Get all techniques mitigated by a specific mitigation (by STIX ID).

    Args:
        mitigation_stix_id: STIX UUID of the mitigation (e.g., course-of-action--UUID).
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Include technique descriptions in the output.

    Returns:
        {
          "found": bool,
          "mitigation": {
              "attack_id": "...",
              "name": "...",
              "stix_id": "course-of-action--..."
          } | null,
          "count": int,
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

    # --- Resolve the mitigation object ---
    mitigation_obj = attack_data.get_object_by_stix_id(mitigation_stix_id)
    if mitigation_obj is None:
        return {
            "found": False,
            "mitigation": None,
            "count": 0,
            "techniques": [],
            "formatted": "",
            "message": (
                f"Mitigation STIX ID '{mitigation_stix_id}' not found in "
                f"domain '{domain}'."
            ),
        }

    mitigation_name = getattr(mitigation_obj, "name", None)
    try:
        mitigation_attack_id = attack_data.get_attack_id(mitigation_stix_id)
    except Exception:
        mitigation_attack_id = None

    # --- Fetch techniques mitigated by this mitigation ---
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
            "techniques": [],
            "formatted": "",
            "message": (
                f"No techniques are mitigated by '{mitigation_attack_id}' "
                f"({mitigation_name}) in domain '{domain}'."
            ),
        }

    # --- Build list of technique entries ---
    technique_entries = []
    unwrapped_techs = []
    for item in techniques:
        t = _unwrap_stix_object(item)
        if t is None:
            continue
        unwrapped_techs.append(t)
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

    formatted = format_objects(
        unwrapped_techs,
        include_description=include_description,
        domain=domain,
    )

    return {
        "found": True,
        "mitigation": {
            "attack_id": mitigation_attack_id,
            "name": mitigation_name,
            "stix_id": mitigation_stix_id,
        },
        "count": len(technique_entries),
        "techniques": technique_entries,
        "formatted": formatted,
        "message": (
            f"Found {len(technique_entries)} techniques mitigated by "
            f"'{mitigation_attack_id}' ({mitigation_name})."
        ),
    }


from typing import Any, Dict, List, Optional

@mcp.tool()
async def get_mitigations_mitigating_technique(
    technique_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = False,
) -> Dict[str, Any]:
    """
    Get all mitigations that address a specific technique.

    Helper returns: list[RelationshipEntry[Mitigation]]
    So each item is a wrapper that contains a Mitigation object (usually in `.object`).
    We must unwrap before extracting fields.

    Returns (same schema as before):
      {
        "found": bool,
        "technique": {...} | null,
        "count": int,
        "mitigations": [...],
        "formatted": str,
        "message": str
      }
    """
    attack_data = get_attack_data(domain)

    # --- Resolve technique context ---
    try:
        technique_obj = attack_data.get_object_by_stix_id(technique_stix_id)
    except Exception:
        technique_obj = None

    if isinstance(technique_obj, dict):
        t_name = technique_obj.get("name")
    else:
        t_name = getattr(technique_obj, "name", None) if technique_obj is not None else None

    try:
        t_attack_id = attack_data.get_attack_id(technique_stix_id)
    except Exception:
        t_attack_id = None

    technique_info = {
        "attack_id": t_attack_id,
        "name": t_name,
        "stix_id": technique_stix_id,
    }

    # --- Fetch relationship entries from MITRE helper ---
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

    def _unwrap_mitigation(entry: Any) -> Any:
        """
        RelationshipEntry[Mitigation] usually stores the Mitigation in `.object`.
        Some implementations may store it in dict["object"].
        """
        # RelationshipEntry object with attribute `.object`
        if hasattr(entry, "object"):
            return getattr(entry, "object")

        # Dict-like wrapper
        if isinstance(entry, dict):
            if isinstance(entry.get("object"), (dict, object)):
                return entry.get("object")

        # If it's already a mitigation (unexpected, but safe)
        return entry

    mitigation_objects: List[Any] = []
    for e in rel_entries:
        m = _unwrap_mitigation(e)
        if m is None:
            continue
        mitigation_objects.append(m)

    mitigation_entries: List[Dict[str, Any]] = []
    for m in mitigation_objects:
        if isinstance(m, dict):
            m_name = m.get("name")
            m_stix = m.get("id")  # STIX ID for course-of-action
            m_desc = m.get("description") if include_description else None
        else:
            m_name = getattr(m, "name", None)
            m_stix = getattr(m, "id", None)
            m_desc = getattr(m, "description", None) if include_description else None

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

    # Format using actual mitigation objects (not relationship entries)
    formatted = format_objects(
        mitigation_objects,
        include_description=include_description,
        domain=domain,
    )

    # Filter out empty rows if any (defensive)
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
        "debug": {
            "raw_relationship_entries": len(rel_entries),
            "unwrapped_mitigations": len(mitigation_objects),
        },
    }


# ---------------------------------------------------------------------------
# Technique → Data components (detection)
# ---------------------------------------------------------------------------
@mcp.tool()
def get_datacomponents_detecting_technique(
    technique_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = False,
) -> dict:
    """
    Get all data components that can detect a specific technique.

    Primary mode:
      - Use mitreattack-python relationship traversal (if present)

    Fallback mode (when relationship traversal yields 0):
      - Read technique.x_mitre_data_sources (strings)
      - Resolve data source objects by name
      - Return data components whose x_mitre_data_source_ref points to those data sources
      - If the string includes a component name (e.g., "Process: Process Creation"),
        filter to that component when possible.

    Returns the same structure as before, plus a debug block.
    """
    attack_data = get_attack_data(domain)

    def _get_attr(obj, name, default=None):
        if obj is None:
            return default
        # support both dict and STIX objects
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

    # ---------- 1) Load technique ----------
    tech_obj = None
    try:
        tech_obj = attack_data.get_object_by_stix_id(technique_stix_id)
    except Exception:
        tech_obj = None

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
    if datacomponents_structured:
        # keep it simple / readable
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
        "technique": technique_info,
        "count": len(datacomponents_structured),
        "datacomponents": datacomponents_structured,
        "detection_strategies": detection_strategies_summary,
        "formatted": formatted,
        "message": message,
    }


@mcp.tool()
async def get_techniques_detected_by_datacomponent(
    datacomponent_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all techniques that can be detected by a specific data component.

    Shows which adversary techniques can be identified by monitoring
    this specific aspect of telemetry.

    Args:
        datacomponent_stix_id: Data component STIX UUID identifier
                               (e.g., 'x-mitre-data-component--UUID').
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Whether to include technique descriptions.

    Returns:
        {
          "datacomponent": {
              "name": "<data component name or null>",
              "stix_id": "<x-mitre-data-component--UUID>",
              "description": "<text or null>",
              "data_source_stix_id": "<x-mitre-data-source--UUID or null>",
              "data_source_name": "<data source name or null>",
              "data_source_attack_id": "<data source ATT&CK ID or null>",
          } | null,

          "count": <number of techniques>,

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

    # --- Resolve data component metadata ---
    try:
        dc_obj = attack_data.get_object_by_stix_id(datacomponent_stix_id)
    except Exception:
        dc_obj = None

    datacomponent_info: Optional[Dict[str, Any]] = None
    dc_for_format: Optional[Any] = None

    if dc_obj is not None:
        dc_for_format = dc_obj

        if isinstance(dc_obj, dict):
            dc_name = dc_obj.get("name")
            dc_desc = dc_obj.get("description") if include_description else None
            ds_ref = (
                dc_obj.get("x_mitre_data_source_ref")
                or dc_obj.get("x-mitre-data-source-ref")
            )
        else:
            dc_name = getattr(dc_obj, "name", None)
            dc_desc = getattr(dc_obj, "description", None) if include_description else None
            ds_ref = getattr(dc_obj, "x_mitre_data_source_ref", None)

        data_source_stix_id = ds_ref
        data_source_name = None
        data_source_attack_id = None

        if ds_ref:
            try:
                ds_obj = attack_data.get_object_by_stix_id(ds_ref)
            except Exception:
                ds_obj = None

            if ds_obj is not None:
                if isinstance(ds_obj, dict):
                    ds_name = ds_obj.get("name")
                    ds_internal_id = ds_obj.get("id")
                else:
                    ds_name = getattr(ds_obj, "name", None)
                    ds_internal_id = getattr(ds_obj, "id", None)

                data_source_name = ds_name
                try:
                    data_source_attack_id = attack_data.get_attack_id(ds_internal_id)
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

    # --- Fetch techniques detected by this data component ---
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
            "datacomponent": datacomponent_info,
            "count": 0,
            "techniques": [],
            "formatted": "",
            "message": (
                f"No techniques found that are detected by data component "
                f"STIX ID '{datacomponent_stix_id}' in domain '{domain}'."
            ),
        }

    # --- Let's build structured list of techniques ---
    technique_entries: List[Dict[str, Any]] = []
    for t in techniques:
        if isinstance(t, dict):
            t_name = t.get("name")
            t_stix = t.get("id")
            t_desc = t.get("description") if include_description else None
        else:
            t_name = getattr(t, "name", None)
            t_stix = getattr(t, "id", None)
            t_desc = getattr(t, "description", None) if include_description else None

        try:
            t_attack_id = attack_data.get_attack_id(t_stix)
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

    # --- Optional human-readable formatted output. Can be silent if needed ---
    formatted = ""
    if techniques:
        formatted = format_objects(
            techniques,
            include_description=include_description,
            domain=domain,
        )

    return {
        "datacomponent": datacomponent_info,
        "count": len(technique_entries),
        "techniques": technique_entries,
        "formatted": formatted,
        "message": (
            f"Found {len(technique_entries)} technique(s) that can be detected by "
            f"data component STIX ID '{datacomponent_stix_id}' in domain '{domain}'."
        ),
    }

# ---------------------------------------------------------------------------
# Technique → Tactic → Procedure Examples (real-world usage)
# ---------------------------------------------------------------------------

@mcp.tool()
async def get_procedure_examples_by_technique(
    technique_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get procedure examples showing how threat groups used a specific technique.

    Procedure examples describe real incident behavior tied to this technique.

    Args:
        technique_stix_id: STIX UUID of the technique
        domain: ATT&CK domain
        include_description: Include descriptions of the examples if available

    Returns:
        {
          "technique": {
              "attack_id": "Txxxx",
              "name": "...",
              "stix_id": "attack-pattern--UUID"
          },
          "count": N,
          "examples": [
              {
                "relationship_id": "relationship--UUID",
                "source_group_attack_id": "Gxxxx",
                "source_group_name": "...",
                "description": "...",
                "stix_id": "relationship--UUID"
              },
              ...
          ],
          "formatted": "<multi-line readable text>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # --- Resolve technique metadata ---
    try:
        tech_obj = attack_data.get_object_by_stix_id(technique_stix_id)
    except Exception:
        tech_obj = None

    if tech_obj:
        tech_name = getattr(tech_obj, "name", None)
        try:
            tech_attack_id = attack_data.get_attack_id(technique_stix_id)
        except Exception:
            tech_attack_id = None
    else:
        tech_name = None
        tech_attack_id = None

    technique_info = {
        "attack_id": tech_attack_id,
        "name": tech_name,
        "stix_id": technique_stix_id,
    }

    # --- Retrieve procedure examples ---
    try:
        examples = attack_data.get_procedure_examples_by_technique(
            technique_stix_id
        ) or []
    except Exception:
        examples = []

    if not examples:
        return {
            "technique": technique_info,
            "count": 0,
            "examples": [],
            "formatted": "",
            "message": (
                f"No procedure examples found for technique '{tech_attack_id}' "
                f"in domain '{domain}'."
            ),
        }

    # --- Parse examples ---
    example_entries = []
    for rel in examples:
        # Relationship STIX ID
        rel_id = getattr(rel, "id", None)

        # Description of the specific usage of this technique
        desc = getattr(rel, "description", None) if include_description else None

        # Source entity (intrusion-set, malware, tool, or campaign)
        source_stix_id = _stix_get(rel, "source_ref")

        src_attack_id = None
        src_name = None
        src_type = source_stix_id.split("--")[0] if isinstance(source_stix_id, str) and "--" in source_stix_id else None
        try:
            src_obj = attack_data.get_object_by_stix_id(source_stix_id)
            if src_obj:
                src_name = _stix_get(src_obj, "name")
                src_type = _stix_get(src_obj, "type") or src_type
                src_attack_id = attack_data.get_attack_id(source_stix_id)
        except Exception:
            pass

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

    # Human-readable lines using resolved entity names instead of raw STIX UUIDs
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
        "technique": technique_info,
        "count": len(example_entries),
        "examples": example_entries,
        "formatted": formatted,
        "message": (
            f"Found {len(example_entries)} procedure examples showing how groups "
            f"used technique '{tech_attack_id}' ({tech_name})."
        ),
    }


@mcp.tool()
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
    formatted = format_objects(
        page_examples,
        include_description=include_description,
        domain=domain,
    )
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

@mcp.tool()
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

    formatted = format_objects(
        page_objs,
        include_description=include_description,
        domain=domain,
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

@mcp.tool()
async def get_tactics_by_matrix(
    matrix_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = False,
):
    """
    Get all ATT&CK tactics belonging to a specific matrix.

    Args:
        matrix_stix_id: STIX ID of the matrix (e.g., x-mitre-matrix--UUID)
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics')
        include_description: Whether to include tactic descriptions

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

    matrix_name = None
    try:
        matrix_obj = attack_data.get_object_by_stix_id(matrix_stix_id)
        matrix_name = _stix_get(matrix_obj, "name") if matrix_obj is not None else None
    except Exception:
        matrix_name = None

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

    formatted = format_objects(
        tactics,
        include_description=include_description,
        domain=domain,
    )

    return {
        "found": True,
        "count": len(results),
        "tactics": results,
        "formatted": formatted,
        "message": f"Found {len(results)} tactic(s) in matrix '{matrix_stix_id}'.",
    }

@mcp.tool()
async def get_tactics_by_technique(
    technique_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = False,
):
    """
    Get all tactics associated with a specific ATT&CK technique.

    Techniques can belong to one or more tactics (kill chain phases).

    Args:
        technique_stix_id: Technique STIX UUID identifier (attack-pattern--UUID)
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics')
        include_description: Whether to include tactic descriptions

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
        stix_id = tac.id

        try:
            attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            attack_id = None

        results.append(
            {
                "name": getattr(tac, "name", None),
                "stix_id": stix_id,
                "attack_id": attack_id,
                "description": getattr(tac, "description", None)
                if include_description
                else None,
            }
        )

    formatted = format_objects(
        tactics,
        include_description=include_description,
        domain=domain,
    )

    return {
        "found": True,
        "count": len(results),
        "tactics": results,
        "formatted": formatted,
        "message": f"Found {len(results)} tactic(s) associated with the technique.",
    }


@mcp.tool()
async def get_objects_created_after(
    timestamp: str,
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
) -> Dict[str, Any]:
    """
    Get all ATT&CK objects created after a specific timestamp.

    Useful for detecting new additions to the framework.
    Timestamp must be ISO8601 format, e.g., '2024-01-01T00:00:00Z'.

    Returns:
        {
            "found": bool,
            "count": int,
            "objects": [
                {
                    "id": "<ATT&CK ID or None>",
                    "name": "...",
                    "stix_id": "...",
                    "type": "<stix-type>",
                    "description": "..." | None
                },
                ...
            ],
            "formatted": "<pretty text>",
            "message": "..."
        }
    """
    attack_data = get_attack_data(domain)

    # Try to fetch objects
    try:
        objects = attack_data.get_objects_created_after(timestamp) or []
    except Exception as e:
        return {
            "found": False,
            "count": 0,
            "objects": [],
            "formatted": "",
            "message": f"Error retrieving objects created after {timestamp}: {e}",
        }

    safe_limit, safe_offset = _validate_pagination(limit, offset)

    if not objects:
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
            "message": f"No objects created after '{timestamp}' in domain '{domain}'.",
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

    # Build structured response
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

    # Pretty printed human-friendly block
    formatted = format_objects(page_objects, include_description=include_description, domain=domain)
    has_more = (safe_offset + len(results)) < total_count

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
        "message": f"Showing {len(results)} of {total_count} objects created after {timestamp} (offset={safe_offset}).",
    }

@mcp.tool()
async def get_objects_modified_after(
    timestamp: str,
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
) -> Dict[str, Any]:
    """
    Get all ATT&CK objects modified after a specific timestamp.

    Useful for tracking updates and changes to the ATT&CK framework.
    Timestamp must be ISO8601 format, e.g., '2024-01-01T00:00:00Z'.

    Returns:
        {
            "found": bool,
            "count": int,
            "objects": [
                {
                    "id": "<ATT&CK ID or None>",
                    "name": "...",
                    "stix_id": "...",
                    "type": "<stix-type>",
                    "description": "..." | None
                },
                ...
            ],
            "formatted": "<pretty text>",
            "message": "..."
        }
    """
    attack_data = get_attack_data(domain)

    # Try to fetch objects
    try:
        objects = attack_data.get_objects_modified_after(timestamp) or []
    except Exception as e:
        return {
            "found": False,
            "count": 0,
            "objects": [],
            "formatted": "",
            "message": f"Error retrieving objects modified after {timestamp}: {e}",
        }

    safe_limit, safe_offset = _validate_pagination(limit, offset)

    if not objects:
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
            "message": f"No objects modified after '{timestamp}' in domain '{domain}'.",
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

    # Build structured response
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

    # Human-readable formatted output
    formatted = format_objects(
        page_objects,
        include_description=include_description,
        domain=domain,
    )
    has_more = (safe_offset + len(results)) < total_count

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
        "message": f"Showing {len(results)} of {total_count} objects modified after {timestamp} (offset={safe_offset}).",
    }

@mcp.tool()
async def get_revoked_techniques(
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all revoked techniques for a domain.

    Revoked techniques are no longer valid in the framework, often because
    they were merged or replaced.

    Returns:
        {
            "found": bool,
            "count": int,
            "techniques": [...],
            "formatted": "<pretty output>",
            "message": "..."
        }
    """
    attack_data = get_attack_data(domain)

    # Retrieve ALL techniques, including revoked ones
    try:
        all_techniques = attack_data.get_techniques(remove_revoked_deprecated=False)
    except Exception as e:
        return {
            "found": False,
            "count": 0,
            "techniques": [],
            "formatted": "",
            "message": f"Error retrieving techniques: {e}",
        }

    # Filter revoked only
    revoked = [t for t in all_techniques if _stix_get(t, "revoked", False)]

    if not revoked:
        return {
            "found": False,
            "count": 0,
            "techniques": [],
            "formatted": "",
            "message": f"No revoked techniques found in domain '{domain}'.",
        }

    # Build structured output
    output_items = []
    for tech in revoked:
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

    # Human-readable formatted block
    formatted = format_objects(
        revoked,
        include_description=include_description,
        domain=domain,
    )

    return {
        "found": True,
        "count": len(output_items),
        "techniques": output_items,
        "formatted": formatted,
        "message": f"Found {len(output_items)} revoked techniques in '{domain}'.",
    }

@mcp.tool()
async def generate_layer(
    attack_id: str,
    score: int = 1,
    domain: str = "enterprise",
) -> Dict[str, Any]:
    """
    Generate an ATT&CK Navigator layer for visualization.

    This wraps mitreattack.navlayers.UsageLayerGenerator and produces a
    JSON layer highlighting techniques associated with a given ATT&CK ID.

    Only the following ATT&CK ID prefixes are supported:
      - Gxxxx : groups (intrusion sets)
      - Mxxxx : mitigations (course-of-action)
      - Sxxxx : software (tool/malware)
      - Dxxxx : data components

    Technique IDs (Txxxx / Txxxx.xxx) are NOT supported here.

    Args:
        attack_id: ATT&CK ID (Gxxxx, Mxxxx, Sxxxx, or Dxxxx)
        score: Score to assign to all matched techniques in the layer
        domain: ATT&CK domain (e.g., "enterprise", "mobile", "ics")

    Returns:
        {
          "success": bool,
          "attack_id": "<G/M/S/D ID>",
          "domain": "<domain>",
          "count": int,              # number of techniques in layer
          "layer": { ... } | null,   # ATT&CK Navigator layer JSON
          "message": "<summary or error>"
        }
    """
    import re
    from mitreattack.navlayers import UsageLayerGenerator

    domain = (domain or "enterprise").strip().lower()
    attack_id = (attack_id or "").strip().upper()

    # Validate ATT&CK ID format: Gxxxx, Mxxxx, Sxxxx, Dxxxx, or DCxxxx (v20.1 data component)
    if not re.match(r"^(?:[GMSD]|DC)\d+$", attack_id):
        return {
            "success": False,
            "attack_id": attack_id,
            "domain": domain,
            "count": 0,
            "layer": None,
            "message": (
                f"Invalid ATT&CK ID format: '{attack_id}'. Must be "
                "GXXXX (group), MXXXX (mitigation), SXXXX (software), or DCXXXX/DXXXX (data component). "
                "Technique IDs (TXXXX) are not supported."
            ),
        }

    stix_path = get_stix_path(domain)
    if not stix_path.exists():
        return {
            "success": False,
            "attack_id": attack_id,
            "domain": domain,
            "count": 0,
            "layer": None,
            "message": f"STIX data for domain '{domain}' is not available.",
        }

    # Generate Navigator layer directly from loaded MitreAttackData for complete v20.1 accuracy
    try:
        ad = get_attack_data(domain)
        src_obj = None
        raw_items: List[Any] = []
        relation_label = "Associated with"

        if attack_id.startswith("G"):
            src_obj = ad.get_object_by_attack_id(attack_id, "intrusion-set")
            if src_obj is not None:
                raw_items = ad.get_techniques_used_by_group(_stix_get(src_obj, "id")) or []
                relation_label = "Used by group"
        elif attack_id.startswith("M"):
            src_obj = ad.get_object_by_attack_id(attack_id, "course-of-action")
            if src_obj is not None:
                raw_items = ad.get_techniques_mitigated_by_mitigation(_stix_get(src_obj, "id")) or []
                relation_label = "Mitigated by"
        elif attack_id.startswith("S"):
            src_obj = ad.get_object_by_attack_id(attack_id, "malware") or ad.get_object_by_attack_id(attack_id, "tool")
            if src_obj is not None:
                raw_items = ad.get_techniques_used_by_software(_stix_get(src_obj, "id")) or []
                relation_label = "Used by software"
        elif attack_id.startswith("DC") or attack_id.startswith("D"):
            src_obj = ad.get_object_by_attack_id(attack_id, "x-mitre-data-component")
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
            return {
                "success": False,
                "attack_id": attack_id,
                "domain": domain,
                "count": 0,
                "layer": None,
                "message": f"ATT&CK object '{attack_id}' was not found in domain '{domain}'.",
            }

        src_name = _stix_get(src_obj, "name") or attack_id
        seen_tids = set()
        tech_entries: List[Dict[str, Any]] = []
        for item in raw_items:
            tobj = _unwrap_stix_object(item)
            if tobj is None or _stix_get(tobj, "revoked", False) or _stix_get(tobj, "x_mitre_deprecated", False):
                continue
            tid = _stix_get(tobj, "id")
            t_aid = ad.get_attack_id(tid) if tid else None
            if not t_aid or t_aid in seen_tids:
                continue
            seen_tids.add(t_aid)

            # Extract concise comment from relationship description if present
            comment = f"{relation_label} {src_name} ({attack_id})"
            if isinstance(item, dict) and item.get("relationships"):
                r_desc = _stix_get(item["relationships"][0], "description")
                if isinstance(r_desc, str) and r_desc.strip():
                    clean_desc = " ".join(r_desc.strip().split())
                    comment = clean_desc[:197] + "..." if len(clean_desc) > 200 else clean_desc

            tech_entries.append({
                "techniqueID": t_aid,
                "score": score,
                "comment": comment,
                "enabled": True,
            })

        if not tech_entries:
            return {
                "success": False,
                "attack_id": attack_id,
                "domain": domain,
                "count": 0,
                "layer": None,
                "message": f"No active techniques found for '{attack_id}' ({src_name}) in domain '{domain}'.",
            }

        layer_dict = {
            "name": f"{src_name} ({attack_id})",
            "versions": {
                "attack": str(release_info.LATEST_VERSION),
                "navigator": "5.1.0",
                "layer": "4.5",
            },
            "domain": f"{domain}-attack",
            "description": f"ATT&CK Navigator layer for {src_name} ({attack_id}) in {domain} v{release_info.LATEST_VERSION}.",
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
            "attack_id": attack_id,
            "domain": domain,
            "count": count,
            "layer": layer_dict,
            "message": (
                f"Generated Navigator layer for '{attack_id}' in domain "
                f"'{domain}' with {count} technique(s)."
            ),
        }

    except Exception as e:
        return {
            "success": False,
            "attack_id": attack_id,
            "domain": domain,
            "count": 0,
            "layer": None,
            "message": f"Failed to generate layer: {e}",
        }

@mcp.tool()
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

    # Domain → platform filter mappings
    domain_configs = {
        "enterprise": {
            "domain": "enterprise-attack",
            "filters": {
                "platforms": [
                    "Windows", "Linux", "macOS", "Network", "PRE",
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
            "filters": {"platforms": ["Embedded", "Linux", "Network Devices", "Windows"]},
        },
    }

    # Normalize domain
    domain = domain.lower()
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



@mcp.tool()
async def get_detection_strategies_for_technique(
    technique_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = False,
) -> Dict[str, Any]:
    """
    Get ATT&CK v20.1 detection strategies (DETxxxx), analytics (ANxxxx), and
    referenced data components (DCxxxx) that detect a given technique.
    """
    ad = get_attack_data(domain)
    v20_idx = _get_v20_detection_index(domain)
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
                "platforms": _stix_get(an_obj, "x_mitre_platforms", []),
                "description": _stix_get(an_obj, "description") if include_description else None,
                "data_components": dc_refs,
            })

        strategies.append({
            "attack_id": ds_aid,
            "name": _stix_get(ds_obj, "name"),
            "stix_id": ds_id,
            "description": _stix_get(ds_obj, "description") if include_description else None,
            "analytics": an_list,
        })

    return {
        "technique_stix_id": technique_stix_id,
        "domain": domain,
        "count": len(strategies),
        "detection_strategies": strategies,
        "message": f"Found {len(strategies)} detection strategy(ies) for '{technique_stix_id}' in domain '{domain}'.",
    }


@mcp.tool()
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
    """
    _validate_pagination(limit, offset)
    ad = get_attack_data(domain)
    v20_idx = _get_v20_detection_index(domain)
    q = (query or "").strip().lower()

    matched = []
    for an_id, an_obj in v20_idx["an_by_id"].items():
        name = _stix_get(an_obj, "name", "") or ""
        desc = _stix_get(an_obj, "description", "") or ""
        if q and q not in name.lower() and q not in desc.lower():
            continue
        matched.append((an_id, an_obj))

    matched.sort(key=lambda pair: str(pair[0] or ""))
    page, total_count, safe_offset, safe_limit, has_more, next_offset = _paginate_items(
        matched, limit=limit, offset=offset
    )

    items = []
    for an_id, an_obj in page:
        try:
            an_aid = ad.get_attack_id(an_id)
        except Exception:
            an_aid = None
        items.append({
            "attack_id": an_aid,
            "name": _stix_get(an_obj, "name"),
            "stix_id": an_id,
            "platforms": _stix_get(an_obj, "x_mitre_platforms", []),
            "data_component_refs": v20_idx["an_to_dcs"].get(an_id, []),
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