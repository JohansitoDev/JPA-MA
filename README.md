# DroidKit

## Por qué creé DroidKit

Creé DroidKit como una herramienta local para ayudarme a revisar APKs Android y proyectos que ya haya extraído. Quiero tener en un mismo lugar un análisis estático inicial, una vista de los resultados y accesos a herramientas de decompilación.

DroidKit sirve como apoyo para revisar aplicaciones propias o para las que tengo autorización. No es un escáner completo de OWASP MASVS, no confirma por sí solo que una coincidencia sea una vulnerabilidad y no reemplaza una auditoría manual.

## Cómo la ejecuto

Desde PowerShell, en la carpeta del proyecto:

```powershell
cd C:\Users\jmancebo\Desktop\JPA-MA
python main.py
```

Esto abre la interfaz de escritorio de cuatro paneles. También puedo iniciarla explícitamente con:

```powershell
python main.py desktop
```

Para ver los comandos de terminal:

```powershell
python main.py --help
```

## Requisitos

- Python 3 con soporte Tk/Tcl para abrir la interfaz gráfica.
- Androguard para analizar APKs. Si no está instalado, puedo instalarlo con:

```powershell
python -m pip install androguard
```

- Apktool, JADX y ADB son opcionales, pero sus ejecutables deben estar en `PATH` para usar sus acciones.

## Qué funciona en el código

### Interfaz de escritorio

- Abre una ventana real hecha con Tkinter, con cuatro paneles oscuros y texto verde.
- Permite seleccionar un APK, iniciar el análisis y ver la salida de las herramientas.
- Dibuja una gráfica con el conteo de los indicadores encontrados. Antes de analizar, la gráfica no contiene resultados.
- Muestra si Androguard, Apktool, JADX y ADB están disponibles en `PATH`.
- Ejecuta las tareas largas en segundo plano para que la ventana siga respondiendo.

### Análisis estático de APK con Androguard

El comando `analizar` intenta abrir el APK local y mostrar:

- Paquete, nombre, versión y SDK mínimo/objetivo.
- Permisos declarados y una selección de permisos sensibles que conviene justificar.
- Indicadores del Manifest: `debuggable`, tráfico HTTP habilitado, `allowBackup=true` y componentes `exported=true`.
- URLs HTTP/HTTPS encontradas como cadenas dentro de los archivos DEX.

Las URLs se buscan en cadenas presentes en el APK; esto no revela tráfico de red ni URLs que se formen dinámicamente durante la ejecución.

```powershell
python main.py analizar "C:\ruta\mi-app.apk"
python main.py analizar "C:\ruta\mi-app.apk" --json reporte.json
```

### Revisión estática de un proyecto extraído

Con `revisar-proyecto` puedo examinar archivos Java, Kotlin, Smali y algunos formatos de recursos. Las reglas buscan patrones que podrían indicar:

- Secretos o credenciales hardcodeados. El reporte indica archivo y línea, no imprime el valor.
- URLs HTTP.
- Uso de MD5, SHA-1, DES, 3DES o AES/ECB.
- Cuerpos posiblemente vacíos en ciertos métodos de validación TLS.
- JavaScript o acceso a archivos habilitado en WebView.

La búsqueda está limitada a archivos de hasta 2 MB, omite carpetas comunes de build/dependencias y muestra como máximo 500 coincidencias. Son reglas heurísticas: pueden producir falsos positivos y no detectan todos los problemas.

```powershell
python main.py revisar-proyecto "C:\ruta\proyecto-extraido"
python main.py revisar-proyecto "C:\ruta\proyecto-extraido" --json reporte.json
```

### Acciones que invocan herramientas externas

También implementé comandos que llaman a herramientas reales; no generan resultados de demostración:

| Acción | Comando | Herramienta necesaria | Resultado |
|---|---|---|---|
| Extraer recursos, Manifest y Smali | `python main.py decodificar "app.apk" -o "proyecto"` | Apktool | Carpeta decodificada |
| Exportar una aproximación de Java | `python main.py decompilar-java "app.apk" -o "java"` | JADX | Código Java aproximado |
| Reconstruir una carpeta decodificada | `python main.py reconstruir "proyecto"` | Apktool | APK sin firmar |
| Listar dispositivos ADB | `python main.py dispositivos` | Android Platform Tools (`adb`) | Salida de `adb devices` |

La salida Java de JADX no es el código fuente original. La reconstrucción no firma ni instala el APK.

## Qué está pendiente o bloqueado en mi entorno

En el entorno donde he comprobado el proyecto:

- Tkinter y Androguard están instalados.
- **Apktool no está instalado o no está en `PATH`**; por eso todavía no puedo comprobar aquí la decodificación ni la reconstrucción real.
- **JADX no está instalado o no está en `PATH`**; la exportación Java no puede ejecutarse aquí.
- **ADB no está instalado o no está en `PATH`**; no puedo listar dispositivos conectados desde DroidKit.
- Todavía no he validado el análisis completo contra un APK real. He comprobado la sintaxis, la interfaz y partes de las reglas con datos de prueba.
- No he integrado MobSF, Burp Suite ni Frida.
- No hago análisis dinámico, captura de tráfico, pruebas de inicio de sesión ni bypass de root o SSL pinning.

Para habilitar Apktool, JADX o ADB, necesito instalarlos por separado y asegurarme de que sus ejecutables estén disponibles en `PATH`. La interfaz muestra cuáles encuentra al iniciarse.

## Archivos principales

- `main.py`: CLI, comandos y lanzamiento de la interfaz.
- `analyzer.py`: análisis del APK y reglas de revisión estática.
- `desktop.py`: interfaz gráfica de cuatro paneles.
