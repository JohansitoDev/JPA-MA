import json
import re
import sys
from pathlib import Path


_REVIEW_PERMISSIONS = {
    "SEND_SMS",
    "READ_SMS",
    "RECEIVE_SMS",
    "READ_CONTACTS",
    "WRITE_CONTACTS",
    "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION",
    "RECORD_AUDIO",
    "CAMERA",
    "READ_EXTERNAL_STORAGE",
    "WRITE_EXTERNAL_STORAGE",
    "READ_PHONE_STATE",
    "CALL_PHONE",
}


def _local_name(name):
    return name.rsplit("}", 1)[-1]


def _attribute(element, name):
    for key, value in element.attrib.items():
        if _local_name(key) == name:
            return value
    return None


def _manifest_findings(manifest):
    findings = []
    application = next(
        (node for node in manifest.iter() if _local_name(node.tag) == "application"),
        None,
    )
    if application is None:
        return findings

    checks = (
        (
            "debuggable",
            "alta",
            "La aplicacion declara android:debuggable=true.",
        ),
        (
            "usesCleartextTraffic",
            "media",
            "La aplicacion permite trafico HTTP sin cifrar.",
        ),
        (
            "allowBackup",
            "revisar",
            "La aplicacion permite copias de seguridad mediante allowBackup=true.",
        ),
    )
    for attribute, severity, description in checks:
        if (_attribute(application, attribute) or "").lower() == "true":
            findings.append(
                {"severity": severity, "category": "Manifest", "detail": description}
            )

    for node in application.iter():
        component = _local_name(node.tag)
        if component not in {"activity", "activity-alias", "service", "receiver", "provider"}:
            continue
        if (_attribute(node, "exported") or "").lower() == "true":
            name = _attribute(node, "name") or "(sin nombre)"
            findings.append(
                {
                    "severity": "revisar",
                    "category": "Componente exportado",
                    "detail": f"{component} {name} esta marcado como exported=true; valida sus controles de acceso.",
                }
            )
    return findings


def _collect_urls(analysis):
    urls = set()
    inspection_errors = 0
    for method in analysis.get_methods():
        try:
            source = method.get_source()
        except (AttributeError, NotImplementedError):
            inspection_errors += 1
            continue
        if source:
            urls.update(re.findall(r'https?://[^\s"\'<>]+', source))
    return sorted(urls), inspection_errors


def analizar_apk(ruta_apk, json_path=None):
    apk_path = Path(ruta_apk).expanduser()
    if not apk_path.is_file() or apk_path.suffix.lower() != ".apk":
        print("[-] Indica la ruta de un archivo APK existente.", file=sys.stderr)
        return False

    try:
        from androguard.misc import AnalyzeAPK
    except ImportError as exc:
        print(
            "[-] Falta Androguard. Instalala con: python -m pip install androguard",
            file=sys.stderr,
        )
        return False

    print(f"\n[+] Analizando: {apk_path}...")
    try:
        app, _dex_files, analysis = AnalyzeAPK(str(apk_path))
        manifest = app.get_android_manifest_xml()
    except Exception as exc:
        print(f"[-] No se pudo analizar el APK: {exc}", file=sys.stderr)
        return False

    package_name = app.get_package()
    permissions = sorted(app.get_permissions() or [])
    findings = _manifest_findings(manifest)
    review_permissions = [
        permission
        for permission in permissions
        if permission.rsplit(".", 1)[-1] in _REVIEW_PERMISSIONS
    ]
    for permission in review_permissions:
        findings.append(
            {
                "severity": "revisar",
                "category": "Permiso sensible",
                "detail": f"{permission} requiere justificar su necesidad y uso.",
            }
        )

    urls, source_errors = _collect_urls(analysis)
    report = {
        "apk": str(apk_path),
        "package": package_name,
        "app_name": app.get_app_name(),
        "version": app.get_androidversion_name(),
        "min_sdk": app.get_min_sdk_version(),
        "target_sdk": app.get_target_sdk_version(),
        "permissions": permissions,
        "findings": findings,
        "urls": urls[:50],
        "methods_not_inspected": source_errors,
    }

    print("\n=== INFORMACION DE LA APLICACION ===")
    print(f"Paquete:      {report['package']}")
    print(f"Nombre:       {report['app_name']}")
    print(f"Version:      {report['version']}")
    print(f"SDK minimo:   {report['min_sdk']}")
    print(f"SDK objetivo: {report['target_sdk']}")

    print("\n=== PERMISOS ===")
    if permissions:
        for permission in permissions:
            marker = "[!]" if permission in review_permissions else "[*]"
            print(f"{marker} {permission}")
    else:
        print("No se declararon permisos.")

    print("\n=== INDICADORES PARA REVISAR ===")
    if findings:
        for item in findings:
            print(f"[{item['severity'].upper()}] {item['category']}: {item['detail']}")
    else:
        print("No se detectaron los indicadores estaticos incluidos en este analisis.")

    print("\n=== URLS ENCONTRADAS EN CODIGO DECOMPILADO ===")
    if urls:
        for url in urls[:50]:
            print(f"[*] {url}")
        if len(urls) > 50:
            print(f"... y {len(urls) - 50} mas (omitidas en pantalla).")
    else:
        print("No se encontraron URLs en las fuentes disponibles.")
    if source_errors:
        print(f"[!] No se pudo inspeccionar el codigo fuente de {source_errors} metodos.")

    if json_path:
        output_path = Path(json_path).expanduser()
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(
                json.dumps(report, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError as exc:
            print(f"[-] No se pudo guardar el JSON: {exc}", file=sys.stderr)
            return False
        print(f"\n[+] Reporte JSON guardado en: {output_path}")

    print("\n[+] Analisis estatico terminado; los indicadores requieren validacion manual.")
    return True
