import contextlib
import importlib.util
import io
import queue
import re
import threading
from pathlib import Path


def launch_desktop(actions):
    import tkinter as tk
    from tkinter import filedialog

    black = "#050805"
    panel_black = "#080d08"
    green = "#39ff14"
    muted_green = "#91c98b"
    border = "#237a23"
    font = "Consolas"
    ansi_escape = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

    root = tk.Tk()
    root.title("DROIDKIT | Android Security Toolkit")
    root.configure(bg=black)
    window_width = min(1440, max(1000, root.winfo_screenwidth() - 80))
    window_height = min(900, max(680, root.winfo_screenheight() - 100))
    root.geometry(f"{window_width}x{window_height}")
    root.minsize(min(1000, window_width), min(680, window_height))
    root.grid_columnconfigure(0, weight=1)
    root.grid_rowconfigure(1, weight=1)

    header = tk.Frame(root, bg=black, padx=18, pady=10)
    header.grid(row=0, column=0, sticky="ew")
    tk.Label(
        header,
        text="DROIDKIT",
        bg=black,
        fg=green,
        font=(font, 25, "bold"),
    ).pack(anchor="w")
    tk.Label(
        header,
        text="ANDROID APP SECURITY  //  LOCAL STATIC WORKBENCH",
        bg=black,
        fg=muted_green,
        font=(font, 10, "bold"),
    ).pack(anchor="w")

    workspace = tk.Frame(root, bg=black, padx=10, pady=6)
    workspace.grid(row=1, column=0, sticky="nsew")
    workspace.grid_columnconfigure(0, weight=1, uniform="panels")
    workspace.grid_columnconfigure(1, weight=1, uniform="panels")
    workspace.grid_rowconfigure(0, weight=1, uniform="panels")
    workspace.grid_rowconfigure(1, weight=1, uniform="panels")

    def make_panel(title, subtitle, row, column):
        frame = tk.Frame(
            workspace,
            bg=panel_black,
            highlightbackground=border,
            highlightthickness=1,
            padx=12,
            pady=9,
        )
        frame.grid(row=row, column=column, sticky="nsew", padx=6, pady=6)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)
        tk.Label(
            frame,
            text=title,
            bg=panel_black,
            fg=green,
            font=(font, 16, "bold"),
            anchor="w",
        ).grid(row=0, column=0, sticky="ew")
        tk.Label(
            frame,
            text=subtitle,
            bg=panel_black,
            fg=muted_green,
            font=(font, 9),
            anchor="w",
        ).grid(row=1, column=0, sticky="ew", pady=(1, 7))
        content = tk.Frame(frame, bg=panel_black)
        content.grid(row=2, column=0, sticky="nsew")
        content.grid_columnconfigure(0, weight=1)
        return frame, content

    def make_text(parent, height=8):
        wrapper = tk.Frame(parent, bg=panel_black)
        wrapper.grid_columnconfigure(0, weight=1)
        wrapper.grid_rowconfigure(0, weight=1)
        widget = tk.Text(
            wrapper,
            height=height,
            bg="#020402",
            fg=green,
            insertbackground=green,
            selectbackground="#195a19",
            font=(font, 10),
            wrap="word",
            relief="flat",
            padx=8,
            pady=6,
        )
        scrollbar = tk.Scrollbar(
            wrapper,
            command=widget.yview,
            bg=panel_black,
            troughcolor=black,
            activebackground=green,
        )
        widget.configure(yscrollcommand=scrollbar.set)
        widget.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        return wrapper, widget

    def set_text(widget, text):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", text.rstrip() + "\n")
        widget.configure(state="disabled")

    def make_button(parent, text, command, row, column=0, columnspan=1):
        button = tk.Button(
            parent,
            text=text,
            command=command,
            bg="#102010",
            fg=green,
            activebackground="#1b3a1b",
            activeforeground=green,
            disabledforeground="#557755",
            font=(font, 9, "bold"),
            relief="groove",
            bd=1,
            padx=9,
            pady=5,
        )
        button.grid(row=row, column=column, columnspan=columnspan, sticky="ew", padx=3, pady=3)
        task_buttons.append(button)
        return button

    task_buttons = []
    busy = [False]
    pending = queue.Queue()

    def process_pending():
        try:
            while True:
                complete, values = pending.get_nowait()
                complete(*values)
        except queue.Empty:
            pass
        root.after(50, process_pending)

    def run_task(label, output, action, on_success=None):
        if busy[0]:
            return
        busy[0] = True
        for button in task_buttons:
            button.configure(state="disabled")
        set_text(output, f"[+] {label}\n[+] Working...")
        captured_out = io.StringIO()
        captured_err = io.StringIO()

        def finish(result, error, output_text, error_text):
            busy[0] = False
            for button in task_buttons:
                button.configure(state="normal")
            output_text = ansi_escape.sub("", output_text)
            error_text = ansi_escape.sub("", error_text)
            if error:
                output_text += f"\n[-] {error}\n"
            if error_text:
                output_text += f"\n{error_text}"
            set_text(output, output_text or "[+] Done.")

            if error:
                status_var.set(f"ERROR  //  {label}")
            elif isinstance(result, bool):
                status_var.set(f"{'DONE' if result else 'FAILED'}  //  {label}")
            elif isinstance(result, int):
                status_var.set(f"{'DONE' if result == 0 else 'FAILED'}  //  {label}")
            else:
                status_var.set(f"DONE  //  {label}")

            task_succeeded = (
                result is True
                or isinstance(result, dict)
                or (
                    isinstance(result, int)
                    and not isinstance(result, bool)
                    and result == 0
                )
            )
            if on_success and error is None and task_succeeded:
                on_success(result)

        def worker():
            result = None
            error = None
            try:
                with contextlib.redirect_stdout(captured_out), contextlib.redirect_stderr(
                    captured_err
                ):
                    result = action()
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
            pending.put(
                (
                    finish,
                    (result, error, captured_out.getvalue(), captured_err.getvalue()),
                )
            )

        threading.Thread(target=worker, daemon=True).start()

    apk_var = tk.StringVar()
    decode_dir_var = tk.StringVar()
    java_dir_var = tk.StringVar()
    project_dir_var = tk.StringVar()
    build_apk_var = tk.StringVar()
    status_var = tk.StringVar(value="READY  //  Select an APK to begin")

    scan_panel, scan_content = make_panel(
        "01  APK SECURITY SCAN",
        "Manifest, permissions, metadata and static indicators",
        0,
        0,
    )
    tk.Label(
        scan_content, text="APK FILE", bg=panel_black, fg=muted_green, font=(font, 9, "bold")
    ).grid(row=0, column=0, sticky="w")
    apk_entry_row = tk.Frame(scan_content, bg=panel_black)
    apk_entry_row.grid(row=1, column=0, sticky="ew")
    apk_entry_row.grid_columnconfigure(0, weight=1)
    tk.Entry(
        apk_entry_row,
        textvariable=apk_var,
        bg="#020402",
        fg=green,
        insertbackground=green,
        relief="flat",
        font=(font, 10),
    ).grid(row=0, column=0, sticky="ew", ipady=6)

    def browse_apk():
        path = filedialog.askopenfilename(
            title="Select an Android APK",
            filetypes=[("Android APK", "*.apk"), ("All files", "*.*")],
        )
        if path:
            apk_var.set(path)

    tk.Button(
        apk_entry_row,
        text="BROWSE",
        command=browse_apk,
        bg="#102010",
        fg=green,
        activebackground="#1b3a1b",
        activeforeground=green,
        font=(font, 9, "bold"),
    ).grid(row=0, column=1, padx=(6, 0))
    scan_buttons = tk.Frame(scan_content, bg=panel_black)
    scan_buttons.grid(row=2, column=0, sticky="ew", pady=4)
    scan_buttons.grid_columnconfigure(0, weight=1)

    scan_output_wrap, scan_output = make_text(scan_content, height=9)
    scan_output_wrap.grid(row=3, column=0, sticky="nsew", pady=(5, 0))
    scan_content.grid_rowconfigure(3, weight=1)

    decode_panel, decode_content = make_panel(
        "02  DECOMPILE / REBUILD",
        "Apktool resources and Smali  |  JADX Java approximation",
        0,
        1,
    )
    decode_content.grid_columnconfigure(1, weight=1)

    def add_path_row(parent, row, label, variable, choose, button_text="FOLDER"):
        tk.Label(
            parent, text=label, bg=panel_black, fg=muted_green, font=(font, 9, "bold")
        ).grid(row=row, column=0, sticky="w", pady=4)
        tk.Entry(
            parent,
            textvariable=variable,
            bg="#020402",
            fg=green,
            insertbackground=green,
            relief="flat",
            font=(font, 9),
        ).grid(row=row, column=1, sticky="ew", padx=4, ipady=4)
        tk.Button(
            parent,
            text=button_text,
            command=choose,
            bg="#102010",
            fg=green,
            activebackground="#1b3a1b",
            activeforeground=green,
            font=(font, 8, "bold"),
        ).grid(row=row, column=2, padx=2)

    def choose_folder(variable, title):
        path = filedialog.askdirectory(title=title)
        if path:
            variable.set(path)

    def choose_output_apk():
        path = filedialog.asksaveasfilename(
            title="Choose rebuilt APK output",
            defaultextension=".apk",
            filetypes=[("Android APK", "*.apk")],
        )
        if path:
            build_apk_var.set(path)

    add_path_row(
        decode_content,
        0,
        "APKTOOL OUTPUT",
        decode_dir_var,
        lambda: choose_folder(decode_dir_var, "Decoded project folder"),
    )
    add_path_row(
        decode_content,
        1,
        "JADX OUTPUT",
        java_dir_var,
        lambda: choose_folder(java_dir_var, "JADX output folder"),
    )
    add_path_row(
        decode_content,
        2,
        "PROJECT FOLDER",
        project_dir_var,
        lambda: choose_folder(project_dir_var, "Decoded project folder"),
    )
    add_path_row(
        decode_content,
        3,
        "REBUILT APK",
        build_apk_var,
        choose_output_apk,
        "SAVE AS",
    )

    tool_buttons = tk.Frame(decode_content, bg=panel_black)
    tool_buttons.grid(row=4, column=0, columnspan=3, sticky="ew", pady=5)
    for column in range(3):
        tool_buttons.grid_columnconfigure(column, weight=1)
    decode_log_wrap, decode_log = make_text(decode_content, height=7)
    decode_log_wrap.grid(row=5, column=0, columnspan=3, sticky="nsew", pady=(5, 0))
    decode_content.grid_rowconfigure(5, weight=1)

    def run_decode():
        apk = apk_var.get().strip()
        output = decode_dir_var.get().strip() or None

        def complete(result):
            if decode_dir_var.get().strip():
                project_dir_var.set(decode_dir_var.get().strip())
            elif apk:
                project_dir_var.set(str(Path(apk).with_suffix("")))

        run_task(
            "APKTOOL DECODE",
            decode_log,
            lambda: actions["decode"](apk, output),
            complete,
        )

    def run_jadx():
        apk = apk_var.get().strip()
        output = java_dir_var.get().strip() or None
        run_task(
            "JADX EXPORT",
            decode_log,
            lambda: actions["jadx"](apk, output),
        )

    def run_build():
        project = project_dir_var.get().strip()
        output = build_apk_var.get().strip() or None
        run_task(
            "APKTOOL BUILD",
            decode_log,
            lambda: actions["build"](project, output),
        )

    make_button(tool_buttons, "DECODE APK", run_decode, 0, 0)
    make_button(tool_buttons, "EXPORT JAVA", run_jadx, 0, 1)
    make_button(tool_buttons, "REBUILD APK", run_build, 0, 2)

    findings_panel, findings_content = make_panel(
        "03  FINDINGS / GRAPH",
        "Heuristic counts only; validate every result manually",
        1,
        0,
    )
    findings_content.grid_rowconfigure(1, weight=1)
    graph = tk.Canvas(
        findings_content,
        height=145,
        bg="#020402",
        highlightthickness=0,
    )
    graph.grid(row=0, column=0, sticky="ew")
    findings_wrap, findings_text = make_text(findings_content, height=7)
    findings_wrap.grid(row=1, column=0, sticky="nsew", pady=(6, 0))

    def update_report(report):
        findings = report.get("findings", [])
        counts = {
            "HIGH": sum(item.get("severity") == "alta" for item in findings),
            "MEDIUM": sum(item.get("severity") == "media" for item in findings),
            "REVIEW": sum(item.get("severity") == "revisar" for item in findings),
        }

        def draw_chart(_event=None):
            graph.delete("all")
            width = max(graph.winfo_width(), 320)
            maximum = max(counts.values(), default=0) or 1
            for index, (label, count) in enumerate(counts.items()):
                y = 28 + index * 36
                graph.create_text(
                    12,
                    y,
                    anchor="w",
                    text=f"{label:<8} {count:>3}",
                    fill=green,
                    font=(font, 10, "bold"),
                )
                bar_x = 112
                bar_max = max(12, width - bar_x - 25)
                bar_width = int(bar_max * count / maximum) if count else 2
                graph.create_rectangle(
                    bar_x,
                    y - 8,
                    bar_x + bar_width,
                    y + 8,
                    fill=green if count else "#164216",
                    outline="",
                )

        graph.bind("<Configure>", draw_chart)
        draw_chart()
        details = []
        if report.get("package"):
            details.append(f"Package: {report['package']}")
            details.append(f"Version: {report.get('version')}")
        details.append(f"Static indicators: {len(findings)}")
        for finding in findings[:100]:
            location = ""
            if finding.get("file"):
                location = f"  {finding['file']}:{finding.get('line', '?')}"
            description = finding.get("detail", finding.get("category", "Review"))
            details.append(
                f"[{str(finding.get('severity', 'review')).upper()}] "
                f"{finding.get('category', 'Indicator')}: {description}{location}"
            )
        if not findings:
            details.append("No matching static indicators.")
        set_text(findings_text, "\n".join(details))

    review_buttons = tk.Frame(findings_content, bg=panel_black)
    review_buttons.grid(row=2, column=0, sticky="ew", pady=(5, 0))
    review_buttons.grid_columnconfigure(0, weight=1)
    review_buttons.grid_columnconfigure(1, weight=1)

    def browse_project():
        choose_folder(project_dir_var, "Select a decoded Apktool/JADX project")

    def run_review():
        project = project_dir_var.get().strip()
        run_task(
            "PROJECT REVIEW",
            scan_output,
            lambda: actions["review"](project),
            lambda report: update_report(report)
            if isinstance(report, dict)
            else None,
        )

    make_button(review_buttons, "REVIEW PROJECT", run_review, 0, 0)
    make_button(
        review_buttons,
        "SELECT PROJECT",
        browse_project,
        0,
        1,
    )

    device_panel, device_content = make_panel(
        "04  TOOLS / DEVICE STATUS",
        "Local tooling and connected-device listing",
        1,
        1,
    )
    device_content.grid_rowconfigure(1, weight=1)
    tool_status_text = tk.Label(
        device_content,
        justify="left",
        anchor="w",
        bg=panel_black,
        fg=muted_green,
        font=(font, 10),
    )
    statuses = [
        f"ANDROGUARD  {'READY' if importlib.util.find_spec('androguard') else 'NOT FOUND'}",
        f"APKTOOL     {actions['tool_status']('apktool')}",
        f"JADX        {actions['tool_status']('jadx')}",
        f"ADB         {actions['tool_status']('adb')}",
    ]
    tool_status_text.configure(text="\n".join(statuses))
    tool_status_text.grid(row=0, column=0, sticky="ew", pady=(0, 6))
    device_log_wrap, device_log = make_text(device_content, height=10)
    device_log_wrap.grid(row=1, column=0, sticky="nsew")
    make_button(
        device_content,
        "LIST ADB DEVICES",
        lambda: run_task("ADB DEVICES", device_log, actions["devices"]),
        2,
    )
    footer = tk.Frame(root, bg=black, padx=16, pady=7)
    footer.grid(row=2, column=0, sticky="ew")
    tk.Label(
        footer,
        textvariable=status_var,
        bg=black,
        fg=green,
        font=(font, 9, "bold"),
        anchor="w",
    ).pack(fill="x")

    def analyze_selected_apk():
        apk = apk_var.get().strip()
        run_task(
            "APK ANALYSIS",
            scan_output,
            lambda: actions["analyze"](apk),
            lambda report: (
                update_report(report),
                set_text(scan_output, f"APK: {report.get('apk')}\nPackage: {report.get('package')}\n"
                                      f"Version: {report.get('version')}\n"
                                      f"Permissions: {len(report.get('permissions', []))}\n"
                                      f"Static findings: {len(report.get('findings', []))}")
            )
            if isinstance(report, dict)
            else None,
        )

    make_button(scan_buttons, "RUN STATIC ANALYSIS", analyze_selected_apk, 0, 0)
    set_text(scan_output, "Choose an APK, then run static analysis.")
    set_text(decode_log, "Tool output will appear here.")
    set_text(findings_text, "Run an APK scan or review an extracted project.")
    set_text(
        device_log,
        "Use the button to list locally connected ADB devices.\n"
        "Static analysis only; no bypass or traffic capture.",
    )

    def close_window():
        if busy[0]:
            status_var.set("WAIT  //  A task is still running")
            return
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", close_window)
    root.after(50, process_pending)
    root.mainloop()
