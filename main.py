import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

from analyzer import analizar_apk


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


def _find_apktool():
    return shutil.which("apktool") or shutil.which("apktool.bat")


def _run_apktool(arguments):
    executable = _find_apktool()
    if not executable:
        terminal.error(
            "No encuentro apktool. Instala la herramienta y verifica que este en PATH."
        )
        return False

    try:
        result = subprocess.run(
            [executable, *map(str, arguments)],
            check=False,
            text=True,
        )
    except OSError as exc:
        terminal.error(f"No se pudo ejecutar apktool: {exc}")
        return False

    return result.returncode == 0


def _decode(apk_path, output_path):
    apk = Path(apk_path).expanduser()
    if not apk.is_file() or apk.suffix.lower() != ".apk":
        terminal.error("Indica la ruta de un archivo APK existente.")
        return 2

    destination = Path(output_path).expanduser() if output_path else apk.with_suffix("")
    if destination.exists():
        terminal.error(f"La carpeta de salida ya existe: {destination}")
        return 2

    terminal.title(f"\nDecodificando {apk.name}")
    if _run_apktool(["d", "-f", "-o", destination, apk]):
        terminal.success(f"Proyecto decodificado en: {destination}")
        return 0
    terminal.error("La decodificacion fallo. Revisa la salida de apktool.")
    return 1


def _build(project_path, output_path):
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
    if not _run_apktool(["b", project, "-o", destination]):
        terminal.error("La reconstruccion fallo. Revisa la salida de apktool.")
        return 1

    terminal.success(f"APK reconstruido en: {destination}")
    terminal.warning("El APK generado no esta firmado; no se instala automaticamente.")
    return 0


def _devices():
    adb = shutil.which("adb")
    if not adb:
        terminal.error("No encuentro adb. Instala Android Platform Tools y configura PATH.")
        return 1
    terminal.title("\nDispositivos conectados")
    try:
        result = subprocess.run([adb, "devices"], check=False, text=True)
    except OSError as exc:
        terminal.error(f"No se pudo ejecutar adb: {exc}")
        return 1
    return result.returncode


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
        elif choice == "0":
            print("  Hasta luego.")
            return 0
        else:
            terminal.error("Opcion no valida.")


def _parser():
    parser = argparse.ArgumentParser(
        prog="droidkit",
        description="CLI local para analisis estatico basico de APKs Android autorizados.",
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
    return parser


def main(argv=None):
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command is None:
        return _interactive_menu()
    if args.command == "analizar":
        return 0 if analizar_apk(args.apk, json_path=args.json) else 1
    if args.command == "decodificar":
        return _decode(args.apk, args.output)
    if args.command == "reconstruir":
        return _build(args.proyecto, args.output)
    if args.command == "dispositivos":
        return _devices()
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
