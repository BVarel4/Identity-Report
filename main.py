from audit import AuditCollector
from config import load_settings
from discovery import build_risk_inventory, discover_risk_types, fetch_risk_details
from parser_registry import build_parser_inventory
from parsers import parse_entities
from reporting import save_report_outputs


def main() -> None:
    settings = load_settings(validate=True)

    print("[*] Iniciando pipeline de Identity Protection...")
    print(f"[*] Dominio objetivo: {settings.target_domain}")

    discovery_nodes, risk_counter, discovery_pages = discover_risk_types(settings)
    risk_inventory = build_risk_inventory(risk_counter)
    parser_inventory = build_parser_inventory(risk_inventory)

    detail_nodes, detail_pages = fetch_risk_details(settings)

    audit = AuditCollector(sample_limit_per_risk=settings.sample_limit_per_risk)
    parsed_risks, attack_paths = parse_entities(
        nodes=detail_nodes,
        audit=audit,
        falcon_base_url=settings.falcon_base_url,
    )

    output_files, warnings = save_report_outputs(
        settings=settings,
        discovery_raw_nodes=discovery_nodes,
        detail_raw_nodes=detail_nodes,
        risk_inventory=risk_inventory,
        parser_inventory=parser_inventory,
        parsed_risks=parsed_risks,
        attack_paths=attack_paths,
        audit=audit,
    )

    total_risk_factors = sum(item["count"] for item in risk_inventory)

    print("\n[+] Pipeline finalizado.")
    print(f"[+] Paginas discovery procesadas: {len(discovery_pages)}")
    print(f"[+] Paginas detail procesadas: {len(detail_pages)}")
    print(f"[+] Entidades discovery: {len(discovery_nodes)}")
    print(f"[+] Entidades detail: {len(detail_nodes)}")
    print(f"[+] Riesgos detectados: {total_risk_factors}")
    print(f"[+] Riesgos parseados: {len(parsed_risks)}")
    print(f"[+] Attack paths parseados: {len(attack_paths)}")

    print("\n[+] Resumen de riesgos detectados:")
    for item in parser_inventory:
        print(
            f"    - {item['risk_type']}: "
            f"{item['count']} | "
            f"{item['percentage']}% | "
            f"parser={item['selected_parser']}"
        )

    print("\n[+] Archivos generados:")
    for name, path in output_files.items():
        print(f"    - {name}: {path}")

    if warnings:
        print("\n[!] Advertencias:")
        for warning in warnings:
            print(f"    - {warning}")


if __name__ == "__main__":
    main()
