import argparse
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

from analyzer import analizar_apk, revisar_proyecto


class Terminal:
    def __init__(self):
        self.color = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

    def _paint(self, text, code):
        if not self.color:
            return text
        return f"\033[{code}m{text}\033[0m"

    def title(self, text):
        print(self._paint(text, "1;36"))

    def success(self, text):
        print(self._paint(f"[+] {text}", "32"))

    def warning(self, text):
        print(self._paint(f"[!] {text}", "33"))

    def error(self, text):
        print(self._paint(f"[-] {text}", "31"))


terminal = Terminal()


def _find_tool(name):
    return shutil.which(name) or shutil.which(f"{name}.bat")


def _run_tool(name, arguments, capture_output=False):
    executable = _find_tool(name)
    if not executable:
        terminal.error(f"No encuentro {name}. Instalala y verifica que este en PATH.")
        return False

    try:
        result = subprocess.run(
            [executable, *map(str, arguments)],
            check=False,
            text=True,
            capture_output=capture_output,
        )
    except OSError as exc:
        terminal.error(f"No se pudo ejecutar {name}: {exc}")
        return False

    if capture_output:
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
    return result.returncode == 0


def _decode_java(apk_path, output_path, capture_output=False):
    apk = Path(apk_path).expanduser()
    if not apk.is_file() or apk.suffix.lower() != ".apk":
        terminal.error("Indica la ruta de un archivo APK existente.")
        return 2

    destination = (
        Path(output_path).expanduser()
        if output_path
        else apk.with_name(f"{apk.stem}_java")
    )
    if destination.exists():
        terminal.error(f"La carpeta de salida ya existe: {destination}")
        return 2

    terminal.title(f"\nExportando codigo Java con JADX: {apk.name}")
    if not _run_tool("jadx", ["-d", destination, apk], capture_output=capture_output):
        terminal.error("La exportacion fallo. Revisa la salida de JADX.")
        return 1
    terminal.success(f"Codigo exportado en: {destination}")
    terminal.warning("La salida de JADX es una aproximacion; no equivale al codigo fuente original.")
    return 0


def _decode(apk_path, output_path, capture_output=False):
    apk = Path(apk_path).expanduser()
    if not apk.is_file() or apk.suffix.lower() != ".apk":
        terminal.error("Indica la ruta de un archivo APK existente.")
        return 2

    destination = Path(output_path).expanduser() if output_path else apk.with_suffix("")
    if destination.exists():
        terminal.error(f"La carpeta de salida ya existe: {destination}")
        return 2

    terminal.title(f"\nDecodificando {apk.name}")
    if _run_tool(
        "apktool", ["d", "-f", "-o", destination, apk], capture_output=capture_output
    ):
        terminal.success(f"Proyecto decodificado en: {destination}")
        return 0
    terminal.error("La decodificacion fallo. Revisa la salida de apktool.")
    return 1


def _build(project_path, output_path, capture_output=False):
    project = Path(project_path).expanduser()
    if not project.is_dir():
        terminal.error("Indica la carpeta de un proyecto decodificado existente.")
        return 2

    destination = (
        Path(output_path).expanduser()
        if output_path
        else project / "dist" / f"{project.name}.apk"
    )
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        terminal.error(f"No se pudo crear la carpeta de salida: {exc}")
        return 1

    terminal.title(f"\nReconstruyendo {project.name}")
    if not _run_tool(
        "apktool", ["b", project, "-o", destination], capture_output=capture_output
    ):
        terminal.error("La reconstruccion fallo. Revisa la salida de apktool.")
        return 1

    terminal.success(f"APK reconstruido en: {destination}")
    terminal.warning("El APK generado no esta firmado; no se instala automaticamente.")
    return 0


def _devices(capture_output=False):
    adb = shutil.which("adb")
    if not adb:
        terminal.error("No encuentro adb. Instala Android Platform Tools y configura PATH.")
        return 1
    terminal.title("\nDispositivos conectados")
    try:
        result = subprocess.run(
            [adb, "devices"],
            check=False,
            text=True,
            capture_output=capture_output,
        )
    except OSError as exc:
        terminal.error(f"No se pudo ejecutar adb: {exc}")
        return 1
    if capture_output:
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
    return result.returncode


def _dashboard_panel(title, body, width, height):
    inner_width = max(1, width - 4)
    lines = [f"+{'-' * (width - 2)}+", f"| {title.upper()[:inner_width].ljust(inner_width)} |"]
    lines.append(f"+{'-' * (width - 2)}+")
    for item in body:
        wrapped = textwrap.wrap(str(item), width=inner_width) or [""]
        lines.extend(f"| {line.ljust(inner_width)} |" for line in wrapped)
    lines = lines[: height - 1]
    lines.extend(["| " + " " * inner_width + " |"] * (height - 1 - len(lines)))
    lines.append(f"+{'-' * (width - 2)}+")
    return lines


def _tool_status(name):
    return "READY" if _find_tool(name) else "NOT FOUND"


def _render_dashboard(state):
    size = shutil.get_terminal_size(fallback=(120, 40))
    panel_width = max(24, (size.columns - 3) // 2)
    panel_height = max(7, (size.lines - 7) // 2)
    report = state.get("report") or {}
    findings = report.get("findings", [])
    counts = {
        "alta": sum(item.get("severity") == "alta" for item in findings),
        "media": sum(item.get("severity") == "media" for item in findings),
        "revisar": sum(item.get("severity") == "revisar" for item in findings),
    }

    apk_info = [
        f"APK: {state.get('apk', 'not selected')}",
        f"Package: {report.get('package', 'n/a')}",
        f"Version: {report.get('version', 'n/a')}",
        f"Permissions: {len(report.get('permissions', []))}",
        f"Static findings: {len(findings)}",
        "Scope: local manifest and code indicators",
    ]
    decompile_info = [
        f"Apktool: {_tool_status('apktool')}",
        f"JADX: {_tool_status('jadx')}",
        f"Decoded project: {state.get('decoded', 'not run')}",
        f"Java export: {state.get('java', 'not run')}",
        f"Rebuilt APK: {state.get('rebuilt', 'not run')}",
    ]
    graph_width = max(1, panel_width - 23)
    graph_info = []
    for label, count in counts.items():
        bar = "#" * min(count, graph_width)
        graph_info.append(f"{label.upper():8} [{bar:<{graph_width}}] {count}")
    if not findings:
        graph_info.append("Run a scan to populate this chart.")

    device_info = [
        f"ADB: {_tool_status('adb')}",
        "Dynamic traffic capture: not enabled",
        "Login/root/pinning bypass: not provided",
    ]
    device_info.extend(state.get("devices", [])[-3:])

    panels = [
        _dashboard_panel("1 / APK SECURITY SCAN", apk_info, panel_width, panel_height),
        _dashboard_panel("2 / DECOMPILE AND REBUILD", decompile_info, panel_width, panel_height),
        _dashboard_panel("3 / FINDINGS GRAPH", graph_info, panel_width, panel_height),
        _dashboard_panel("4 / DEVICES AND SCOPE", device_info, panel_width, panel_height),
    ]
    output = []
    output.extend("  ".join(row) for row in zip(panels[0], panels[1]))
    output.append("")
    output.extend("  ".join(row) for row in zip(panels[2], panels[3]))
    output.extend(
        [
            "",
            "[1] Analyze APK  [2] Apktool decode  [3] JADX Java  [4] Review folder",
            "[5] Apktool build  [6] adb devices  [R] Refresh  [Q] Quit",
        ]
    )

    if sys.stdout.isatty() and os.environ.get("NO_COLOR") is None:
        sys.stdout.write("\033[40;32;1m\033[2J\033[H")
        sys.stdout.write("\n".join(output))
        sys.stdout.write("\033[0m\n")
    else:
        print("\n".join(output))


def _dashboard():
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        terminal.error("El dashboard requiere una terminal interactiva.")
        return 2

    state = {}
    while True:
        _render_dashboard(state)
        try:
            choice = input("\ndroidkit[2x2]> ").strip().lower()
        except EOFError:
            return 0
        if choice == "q":
            print("\033[0m")
            return 0
        if choice == "r":
            continue
        if choice == "1":
            apk = input("APK path: ").strip().strip('"')
            report = analizar_apk(apk)
            if isinstance(report, dict):
                state["apk"] = report["apk"]
                state["report"] = report
        elif choice == "2":
            apk = input("APK path: ").strip().strip('"')
            output = input("Decoded folder (Enter for default): ").strip()
            status = _decode(apk, output or None)
            if status == 0:
                state["decoded"] = output or str(Path(apk).expanduser().with_suffix(""))
        elif choice == "3":
            apk = input("APK path: ").strip().strip('"')
            output = input("Java output folder (Enter for default): ").strip()
            status = _decode_java(apk, output or None)
            if status == 0:
                state["java"] = output or str(
                    Path(apk).expanduser().with_name(
                        f"{Path(apk).stem}_java"
                    )
                )
        elif choice == "4":
            project = input("Decoded project folder: ").strip().strip('"')
            report = revisar_proyecto(project)
            if isinstance(report, dict):
                state["report"] = report
        elif choice == "5":
            project = input("Decoded project folder: ").strip().strip('"')
            output = input("Output APK path (Enter for default): ").strip()
            status = _build(project, output or None)
            if status == 0:
                state["rebuilt"] = output or str(
                    Path(project).expanduser() / "dist" / f"{Path(project).name}.apk"
                )
        elif choice == "6":
            adb = shutil.which("adb")
            if not adb:
                state["devices"] = ["adb not installed."]
            else:
                try:
                    result = subprocess.run(
                        [adb, "devices"],
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    state["devices"] = (result.stdout or result.stderr).splitlines()
                    if result.returncode != 0:
                        state["devices"].append(f"adb exited with code {result.returncode}")
                except OSError as exc:
                    state["devices"] = [f"adb failed: {exc}"]
        else:
            terminal.error("Choose an option from the dashboard.")

        input("\nPress Enter to return to the dashboard...")


def _interactive_menu():
    while True:
        terminal.title(
            "\n"
            "+-------------------------------------------+\n"
            "| DROIDKIT // ANDROID SECURITY TOOLKIT      |\n"
            "+-------------------------------------------+"
        )
        print("  [1] Analizar APK")
        print("  [2] Decodificar APK (apktool)")
        print("  [3] Reconstruir proyecto (apktool)")
        print("  [4] Ver dispositivos (adb)")
        print("  [5] Exportar codigo Java (jadx)")
        print("  [6] Revisar carpeta de codigo/recursos")
        print("  [7] Abrir dashboard 2x2")
        print("  [0] Salir")
        choice = input("\n  droidkit> ").strip()

        if choice == "1":
            apk = input("  Ruta del APK: ").strip().strip('"')
            analizar_apk(apk)
        elif choice == "2":
            apk = input("  Ruta del APK: ").strip().strip('"')
            output = input("  Carpeta destino (Enter para usar el nombre del APK): ").strip()
            _decode(apk, output or None)
        elif choice == "3":
            project = input("  Carpeta del proyecto decodificado: ").strip().strip('"')
            output = input("  APK destino (Enter para usar dist/<proyecto>.apk): ").strip()
            _build(project, output or None)
        elif choice == "4":
            _devices()
        elif choice == "5":
            apk = input("  Ruta del APK: ").strip().strip('"')
            output = input("  Carpeta destino (Enter para usar <apk>_java): ").strip()
            _decode_java(apk, output or None)
        elif choice == "6":
            project = input("  Carpeta decodificada: ").strip().strip('"')
            revisar_proyecto(project)
        elif choice == "7":
            _dashboard()
        elif choice == "0":
            print("  Hasta luego.")
            return 0
        else:
            terminal.error("Opcion no valida.")


def _parser():
    parser = argparse.ArgumentParser(
        prog="droidkit",
        description="Herramienta local para analisis estatico de APKs Android autorizados.",
    )
    commands = parser.add_subparsers(dest="command")

    scan = commands.add_parser("analizar", help="Analizar permisos y ajustes del APK")
    scan.add_argument("apk", help="Ruta al archivo APK")
    scan.add_argument(
        "--json",
        metavar="ARCHIVO",
        help="Guardar tambien el resultado del analisis en JSON",
    )

    decode = commands.add_parser("decodificar", help="Decodificar un APK con apktool")
    decode.add_argument("apk", help="Ruta al archivo APK")
    decode.add_argument("-o", "--output", help="Carpeta destino")

    build = commands.add_parser(
        "reconstruir", help="Reconstruir un proyecto decodificado con apktool"
    )
    build.add_argument("proyecto", help="Carpeta del proyecto apktool")
    build.add_argument("-o", "--output", help="Ruta del APK de salida")

    commands.add_parser("dispositivos", help="Listar dispositivos con adb")
    commands.add_parser("dashboard", help="Abrir el dashboard de terminal en 4 paneles")
    commands.add_parser("desktop", help="Abrir la interfaz grafica de escritorio")
    commands.add_parser("menu", help="Abrir el menu interactivo de terminal")
    jadx = commands.add_parser(
        "decompilar-java", help="Exportar una aproximacion Java con JADX"
    )
    jadx.add_argument("apk", help="Ruta al archivo APK")
    jadx.add_argument("-o", "--output", help="Carpeta destino")

    review = commands.add_parser(
        "revisar-proyecto",
        help="Buscar indicadores heuristicos en codigo y recursos ya extraidos",
    )
    review.add_argument("proyecto", help="Carpeta de Apktool o JADX")
    review.add_argument("--json", metavar="ARCHIVO", help="Guardar el reporte en JSON")
    return parser


def main(argv=None):
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command is None:
        return _launch_desktop()
    if args.command == "analizar":
        return 0 if analizar_apk(args.apk, json_path=args.json) else 1
    if args.command == "decodificar":
        return _decode(args.apk, args.output)
    if args.command == "reconstruir":
        return _build(args.proyecto, args.output)
    if args.command == "dispositivos":
        return _devices()
    if args.command == "dashboard":
        return _dashboard()
    if args.command == "desktop":
        return _launch_desktop()
    if args.command == "menu":
        return _interactive_menu()
    if args.command == "decompilar-java":
        return _decode_java(args.apk, args.output)
    if args.command == "revisar-proyecto":
        return 0 if revisar_proyecto(args.proyecto, json_path=args.json) else 1
    parser.print_help()
    return 2


def _launch_desktop():
    try:
        from desktop import launch_desktop
    except ImportError as exc:
        terminal.error(f"No se pudo iniciar la interfaz grafica: {exc}")
        return 1

    actions = {
        "analyze": analizar_apk,
        "review": revisar_proyecto,
        "decode": lambda apk, output: _decode(apk, output, capture_output=True),
        "jadx": lambda apk, output: _decode_java(
            apk, output, capture_output=True
        ),
        "build": lambda project, output: _build(
            project, output, capture_output=True
        ),
        "devices": lambda: _devices(capture_output=True),
        "tool_status": _tool_status,
    }
    try:
        launch_desktop(actions)
    except ImportError as exc:
        terminal.error(
            f"No se pudo cargar Tkinter. Instala Python con soporte Tcl/Tk: {exc}"
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
