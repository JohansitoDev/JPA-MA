import json
import os
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

_SOURCE_SUFFIXES = {
    ".java",
    ".kt",
    ".smali",
    ".xml",
    ".json",
    ".properties",
    ".txt",
    ".yaml",
    ".yml",
    ".gradle",
    ".js",
    ".html",
    ".cfg",
    ".ini",
}
_SKIP_DIRECTORIES = {".git", ".gradle", "build", "dist", "node_modules", "__pycache__"}
_MAX_SOURCE_BYTES = 2 * 1024 * 1024
_MAX_FINDINGS = 500
_PROJECT_RULES = (
    (
        "alta",
        "Posible secreto hardcodeado",
        re.compile(
            r"""(?i)\b(?:api[_-]?key|client[_-]?secret|password|passwd|token|secret)\b\s*[:=]\s*["'][^"'\s]{4,}["']"""
        ),
    ),
    (
        "media",
        "URL HTTP",
        re.compile(r"""(?i)\bhttp://[^\s"'<>]+"""),
    ),
    (
        "revisar",
        "Criptografia debil",
        re.compile(r"""(?i)\b(?:md5|sha-?1|3des|des)\b|aes\s*/\s*ecb"""),
    ),
    (
        "revisar",
        "Validacion TLS posiblemente debil",
        re.compile(
            r"""(?is)(?:checkServerTrusted|verify)\s*\([^)]*\)\s*\{\s*(?:(?:/\*.*?\*/)|(?://[^\n]*))*\s*\}"""
        ),
    ),
    (
        "revisar",
        "JavaScript habilitado en WebView",
        re.compile(r"""(?i)\bsetJavaScriptEnabled\s*\(\s*true\s*\)"""),
    ),
    (
        "revisar",
        "Acceso a archivos habilitado en WebView",
        re.compile(
            r"""(?i)\bset(?:AllowFileAccess|AllowUniversalAccessFromFileURLs)\s*\(\s*true\s*\)"""
        ),
    ),
)


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


def _collect_urls(dex_files):
    urls = set()
    inspection_errors = 0
    for dex_file in dex_files:
        try:
            strings = dex_file.get_strings()
        except (AttributeError, NotImplementedError):
            inspection_errors += 1
            continue
        for value in strings:
            urls.update(re.findall(r'https?://[^\s"\'<>]+', value))
    return sorted(urls), inspection_errors


def revisar_proyecto(ruta_proyecto, json_path=None):
    root = Path(ruta_proyecto).expanduser()
    if not root.is_dir():
        print("[-] Indica una carpeta de proyecto existente.", file=sys.stderr)
        return False

    findings = []
    warnings = []
    scanned_files = 0
    for current, directories, filenames in os.walk(root, followlinks=False):
        directories[:] = [
            name
            for name in directories
            if name not in _SKIP_DIRECTORIES
            and not (Path(current) / name).is_symlink()
        ]
        for filename in filenames:
            path = Path(current) / filename
            if path.suffix.lower() not in _SOURCE_SUFFIXES or path.is_symlink():
                continue
            try:
                if path.stat().st_size > _MAX_SOURCE_BYTES:
                    warnings.append(f"{path.relative_to(root)} supera 2 MB; omitido.")
                    continue
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                warnings.append(f"No se pudo leer {path.relative_to(root)}: {exc}")
                continue

            scanned_files += 1
            for severity, category, pattern in _PROJECT_RULES:
                for match in pattern.finditer(content):
                    line = content.count("\n", 0, match.start()) + 1
                    findings.append(
                        {
                            "severity": severity,
                            "category": category,
                            "file": str(path.relative_to(root)),
                            "line": line,
                        }
                    )
                    if len(findings) >= _MAX_FINDINGS:
                        warnings.append(
                            f"Se alcanzo el limite de {_MAX_FINDINGS} hallazgos."
                        )
                        break
                if len(findings) >= _MAX_FINDINGS:
                    break
            if len(findings) >= _MAX_FINDINGS:
                break
        if len(findings) >= _MAX_FINDINGS:
            break

    report = {
        "project": str(root),
        "files_scanned": scanned_files,
        "findings": findings,
        "warnings": warnings,
    }

    print(f"\n[+] Revision estatica local: {root}")
    print(f"Archivos revisados: {scanned_files}")
    if findings:
        for finding in findings:
            print(
                f"[{finding['severity'].upper()}] {finding['category']}: "
                f"{finding['file']}:{finding['line']}"
            )
    else:
        print("No se encontraron coincidencias de las reglas incluidas.")
    for warning in warnings:
        print(f"[!] {warning}")
    print("[!] Son coincidencias heuristicas; revisa el codigo y el contexto manualmente.")

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
        print(f"[+] Reporte JSON guardado en: {output_path}")
    return report


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
        app, dex_files, _analysis = AnalyzeAPK(str(apk_path))
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

    urls, dex_errors = _collect_urls(dex_files)
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
        "dex_files_not_inspected": dex_errors,
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

    print("\n=== URLS ENCONTRADAS EN CADENAS DEX ===")
    if urls:
        for url in urls[:50]:
            print(f"[*] {url}")
        if len(urls) > 50:
            print(f"... y {len(urls) - 50} mas (omitidas en pantalla).")
    else:
        print("No se encontraron URLs en las fuentes disponibles.")
    if dex_errors:
        print(f"[!] No se pudieron leer las cadenas de {dex_errors} archivos DEX.")

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
    return report
