"""CrowdStrike GraphQL access layer with automatic pagination support."""

from collections import Counter
from typing import Any

from config import Settings
from queries import DETAIL_QUERY, DISCOVERY_QUERY
from utils import print_progress, print_section, print_status


def get_falcon_client(settings: Settings):
    """Instantiate the FalconPy Identity Protection client."""
    try:
        from falconpy import IdentityProtection
    except ImportError as exc:
        raise RuntimeError(
            "No se encontro 'falconpy'. Instala la dependencia "
            "'crowdstrike-falconpy' antes de ejecutar el pipeline."
        ) from exc

    return IdentityProtection(
        client_id=settings.client_id,
        client_secret=settings.client_secret,
        base_url=settings.falcon_base_url,
    )


def execute_graphql_query(falcon: Any, query: str, variables: dict) -> dict:
    """Execute one GraphQL request and raise on HTTP or GraphQL-level errors."""
    response = falcon.graphql(query=query, variables=variables)

    if response.get("status_code") != 200:
        raise RuntimeError(f"Error HTTP en GraphQL: {response}")

    body = response.get("body", {})
    if "errors" in body:
        raise RuntimeError(f"GraphQL devolvio errores: {body['errors']}")

    return body


def paginate_entities(
    settings: Settings,
    query: str,
    progress_label: str,
) -> tuple[list[dict], list[dict]]:
    """Fetch every entity page for a query and return nodes plus page history."""
    falcon = get_falcon_client(settings)
    print_section(
        f"Fase {progress_label}",
        f"Consulta GraphQL paginada sobre dominio {settings.target_domain}",
    )

    after = None
    all_nodes: list[dict] = []
    page_history: list[dict] = []
    page_number = 0

    while True:
        page_number += 1

        variables = {
            "after": after,
            "domains": [settings.target_domain],
            "first": settings.page_size,
        }

        body = execute_graphql_query(falcon, query, variables)

        entities = body.get("data", {}).get("entities", {})
        nodes = entities.get("nodes", []) or []
        page_info = entities.get("pageInfo", {}) or {}

        all_nodes.extend(nodes)
        page_history.append(
            {
                "page_number": page_number,
                "nodes": len(nodes),
                "has_next_page": page_info.get("hasNextPage", False),
                "end_cursor": page_info.get("endCursor", ""),
            }
        )

        print_progress(
            label=progress_label,
            page_number=page_number,
            nodes_in_page=len(nodes),
            page_size=settings.page_size,
            total_nodes=len(all_nodes),
        )

        if not page_info.get("hasNextPage"):
            break

        after = page_info.get("endCursor")
        if not after:
            raise RuntimeError(
                "GraphQL indico que hay mas paginas pero no devolvio endCursor."
            )

    print_status(
        progress_label,
        f"completado | paginas={page_number} | nodos_totales={len(all_nodes)}",
        tone="success",
    )
    return all_nodes, page_history


def discover_risk_types(settings: Settings) -> tuple[list[dict], Counter, list[dict]]:
    """Run the discovery phase and count risk types observed in the domain."""
    all_nodes, page_history = paginate_entities(
        settings=settings,
        query=DISCOVERY_QUERY,
        progress_label="Discovery",
    )

    risk_counter = Counter()
    for node in all_nodes:
        for risk_factor in node.get("riskFactors", []) or []:
            risk_type = risk_factor.get("type")
            if risk_type:
                risk_counter[risk_type] += 1

    return all_nodes, risk_counter, page_history


def fetch_risk_details(settings: Settings) -> tuple[list[dict], list[dict]]:
    """Run the detail phase using the richer GraphQL query."""
    return paginate_entities(
        settings=settings,
        query=DETAIL_QUERY,
        progress_label="Detail",
    )


def build_risk_inventory(risk_counter: Counter) -> list[dict]:
    """Convert raw counters into sorted rows with percentages for reporting."""
    total = sum(risk_counter.values())
    inventory = []

    for risk_type, count in risk_counter.most_common():
        inventory.append(
            {
                "risk_type": risk_type,
                "count": count,
                "percentage": round((count / total) * 100, 2) if total else 0,
            }
        )

    return inventory
