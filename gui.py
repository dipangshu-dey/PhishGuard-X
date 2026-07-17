import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading

# Import backend
try:
    from analyzer import analyze_url, analyze_email, analyze_sms, analyze_file
    from reporter import ForensicReportGenerator
    REPORTER_ENGINE = ForensicReportGenerator()
    BACKEND_ONLINE = True
except Exception as e:
    print(f"[!] Critical Error loading backend engines: {e}")
    BACKEND_ONLINE = False

try:
    from qr_scanner import scan_qr_for_phishing
    QR_ONLINE = True
except Exception as e:
    print(f"[!] QR scanner not available: {e}")
    QR_ONLINE = False

# -------------------------------------------------- #
#  Constants
# -------------------------------------------------- #

BG           = "#f5f5f5"
FONT_LABEL   = ("Arial", 9)
FONT_BOLD    = ("Arial", 10, "bold")
FONT_TITLE   = ("Arial", 18, "bold")
FONT_MONO    = ("Courier", 9)
FONT_VERDICT = ("Arial", 15, "bold")

BTN_ANALYZE = {"bg": "#4CAF50", "fg": "white", "activebackground": "#45a049",
               "activeforeground": "white", "relief": "flat", "cursor": "hand2"}
BTN_REPORT  = {"bg": "#2196F3", "fg": "white", "activebackground": "#1976D2",
               "activeforeground": "white", "relief": "flat", "cursor": "hand2"}
BTN_CLEAR   = {"bg": "#9E9E9E", "fg": "white", "activebackground": "#757575",
               "activeforeground": "white", "relief": "flat", "cursor": "hand2"}

VERDICT_COLORS = {
    "SAFE":       "green",
    "SUSPICIOUS": "darkorange",
    "PHISHING":   "red",
    "UNKNOWN":    "black",
}


# -------------------------------------------------- #
#  App
# -------------------------------------------------- #

class PhishGuardApp:

    def __init__(self, root_window):
        self.root = root_window
        self.root.title("PhishGuard X — Phishing Detection & Forensic Analysis")
        self.root.geometry("860x720")
        self.root.configure(bg=BG, padx=14, pady=12)
        self.root.resizable(True, True)

        self.last_pdf_path = None
        self._result_data  = None

        self._build_ui()

    # -------------------------------------------------- #
    #  UI — top-level builder
    # -------------------------------------------------- #

    def _build_ui(self):
        self._build_header()
        self._build_input_section()
        self._build_button_section()
        self._build_result_section()
        self._build_pipeline_section()
        self._build_logs_section()

    # ---- Header ---- #

    def _build_header(self):
        frame = tk.Frame(self.root, bg=BG)
        frame.pack(fill="x", pady=(0, 6))

        tk.Label(
            frame,
            text="PhishGuard X",
            font=FONT_TITLE,
            bg=BG
        ).pack(side="left")

        tk.Label(
            frame,
            text="NFSU  —  Cybersecurity Minor Project",
            font=FONT_LABEL,
            fg="gray",
            bg=BG
        ).pack(side="right", anchor="s", pady=4)

        tk.Frame(self.root, bg="#cccccc", height=1).pack(fill="x", pady=(0, 6))

    # ---- Input ---- #

    def _build_input_section(self):
        frame = tk.LabelFrame(
            self.root,
            text="  Input  ",
            font=FONT_BOLD,
            bg=BG,
            padx=10, pady=8
        )
        frame.pack(fill="x", pady=(0, 6))

        # Input type row
        type_row = tk.Frame(frame, bg=BG)
        type_row.pack(fill="x", pady=(0, 5))

        tk.Label(
            type_row,
            text="Input Type:",
            font=FONT_LABEL,
            bg=BG
        ).pack(side="left", padx=(0, 6))

        self.input_type = tk.StringVar(value="URL")
        self.type_combo = ttk.Combobox(
            type_row,
            textvariable=self.input_type,
            values=["URL", "Email", "SMS", "File Path", "QR Code"],
            state="readonly",
            width=16,
            font=FONT_LABEL
        )
        self.type_combo.pack(side="left")
        self.type_combo.bind("<<ComboboxSelected>>", self._on_type_change)

        # Browse button (shown only for File Path and QR Code)
        self.browse_btn = tk.Button(
            type_row,
            text="Browse...",
            font=FONT_LABEL,
            bg="#607D8B",
            fg="white",
            activebackground="#455A64",
            activeforeground="white",
            relief="flat",
            cursor="hand2",
            command=self._browse_file
        )
        # Not packed yet — shown dynamically

        # Hint label
        self.hint_var = tk.StringVar(value="Enter URL / message / file path below:")
        tk.Label(
            frame,
            textvariable=self.hint_var,
            font=FONT_LABEL,
            bg=BG
        ).pack(anchor="w")

        self.target_input = tk.Text(
            frame,
            height=4,
            font=("Arial", 10),
            relief="solid",
            bd=1,
            wrap="word"
        )
        self.target_input.pack(fill="x", pady=(4, 0))

        # Ctrl+Enter shortcut
        self.target_input.bind("<Control-Return>", lambda e: self.execute_analysis())

    def _on_type_change(self, event=None):
        scan_type = self.input_type.get()
        if scan_type == "QR Code":
            self.hint_var.set("Enter QR code image path below (or use Browse):")
            self.browse_btn.pack(side="left", padx=(8, 0))
        elif scan_type == "File Path":
            self.hint_var.set("Enter file path below (or use Browse):")
            self.browse_btn.pack(side="left", padx=(8, 0))
        else:
            self.hint_var.set("Enter URL / message / file path below:")
            self.browse_btn.pack_forget()

    def _browse_file(self):
        scan_type = self.input_type.get()
        if scan_type == "QR Code":
            path = filedialog.askopenfilename(
                title="Select QR Code Image",
                filetypes=[("Image Files", "*.png *.jpg *.jpeg *.bmp *.gif *.tiff"), ("All Files", "*.*")]
            )
        else:
            path = filedialog.askopenfilename(
                title="Select File",
                filetypes=[("All Files", "*.*")]
            )
        if path:
            self.target_input.delete("1.0", tk.END)
            self.target_input.insert("1.0", path)

    # ---- Buttons ---- #

    def _build_button_section(self):
        frame = tk.Frame(self.root, bg=BG)
        frame.pack(fill="x", pady=(0, 6))

        tk.Button(
            frame,
            text="Run Analysis",
            width=16,
            font=FONT_LABEL,
            command=self.execute_analysis,
            **BTN_ANALYZE
        ).grid(row=0, column=0, padx=(0, 6))

        tk.Button(
            frame,
            text="View Report",
            width=16,
            font=FONT_LABEL,
            command=self.open_pdf,
            **BTN_REPORT
        ).grid(row=0, column=1, padx=(0, 6))

        tk.Button(
            frame,
            text="Clear",
            width=10,
            font=FONT_LABEL,
            command=self.clear_workspace,
            **BTN_CLEAR
        ).grid(row=0, column=2)

    # ---- Result ---- #

    def _build_result_section(self):
        frame = tk.LabelFrame(
            self.root,
            text="  Result  ",
            font=FONT_BOLD,
            bg=BG,
            padx=10, pady=8
        )
        frame.pack(fill="x", pady=(0, 6))

        self.verdict_var    = tk.StringVar(value="—")
        self.score_var      = tk.StringVar(value="—")
        self.confidence_var = tk.StringVar(value="—")
        self.attack_var     = tk.StringVar(value="—")

        col1 = tk.Frame(frame, bg=BG)
        col1.grid(row=0, column=0, padx=(0, 30), sticky="w")
        tk.Label(col1, text="Verdict", font=FONT_LABEL, fg="gray", bg=BG).pack(anchor="w")
        self.verdict_label = tk.Label(
            col1,
            textvariable=self.verdict_var,
            font=FONT_VERDICT,
            bg=BG
        )
        self.verdict_label.pack(anchor="w")

        col2 = tk.Frame(frame, bg=BG)
        col2.grid(row=0, column=1, padx=(0, 30), sticky="w")
        tk.Label(col2, text="Risk Score", font=FONT_LABEL, fg="gray", bg=BG).pack(anchor="w")
        tk.Label(col2, textvariable=self.score_var, font=("Arial", 13), bg=BG).pack(anchor="w")

        col3 = tk.Frame(frame, bg=BG)
        col3.grid(row=0, column=2, padx=(0, 30), sticky="w")
        tk.Label(col3, text="ML Confidence", font=FONT_LABEL, fg="gray", bg=BG).pack(anchor="w")
        tk.Label(col3, textvariable=self.confidence_var, font=("Arial", 13), bg=BG).pack(anchor="w")

        col4 = tk.Frame(frame, bg=BG)
        col4.grid(row=0, column=3, sticky="w")
        tk.Label(col4, text="Attack Type", font=FONT_LABEL, fg="gray", bg=BG).pack(anchor="w")
        tk.Label(col4, textvariable=self.attack_var, font=("Arial", 11), bg=BG).pack(anchor="w")

    # ---- Pipeline ---- #

    def _build_pipeline_section(self):
        frame = tk.LabelFrame(
            self.root,
            text="  Execution Pipeline  ",
            font=FONT_BOLD,
            bg=BG,
            padx=10, pady=8
        )
        frame.pack(fill="x", pady=(0, 6))

        self.backend_panel = scrolledtext.ScrolledText(
            frame,
            height=6,
            font=FONT_MONO,
            state="disabled",
            relief="solid",
            bd=1,
            wrap="word"
        )
        self.backend_panel.pack(fill="x")

    # ---- Logs ---- #

    def _build_logs_section(self):
        frame = tk.LabelFrame(
            self.root,
            text="  Analysis Logs  ",
            font=FONT_BOLD,
            bg=BG,
            padx=10, pady=8
        )
        frame.pack(fill="both", expand=True, pady=(0, 0))

        self.console = scrolledtext.ScrolledText(
            frame,
            height=10,
            font=FONT_MONO,
            state="disabled",
            relief="solid",
            bd=1,
            wrap="word"
        )
        self.console.pack(fill="both", expand=True)

    # -------------------------------------------------- #
    #  Write helpers
    # -------------------------------------------------- #

    def _write(self, widget: scrolledtext.ScrolledText, text: str):
        """Thread-safe write to any ScrolledText widget."""
        def _do():
            widget.configure(state="normal")
            widget.insert(tk.END, text + "\n")
            widget.see(tk.END)
            widget.configure(state="disabled")
        self.root.after(0, _do)

    def print_to_console(self, text: str):
        self._write(self.console, text)

    def print_to_pipeline(self, text: str):
        self._write(self.backend_panel, text)

    # -------------------------------------------------- #
    #  Pipeline display
    # -------------------------------------------------- #

    def _show_pipeline(self, include_qr=False):
        steps = []
        if include_qr:
            steps.append("QR Code Decoding")
        steps += [
            "Feature Extraction",
            "Machine Learning Analysis",
            "Rule-Based Detection",
            "Attack Classification",
            "Impact Simulation",
            "Report Generation",
        ]
        for step in steps:
            self.print_to_pipeline(f"[OK]  {step}")

    # -------------------------------------------------- #
    #  Result display
    # -------------------------------------------------- #

    def _show_result(self, result: dict):
        verdict = result.get("verdict", "UNKNOWN")
        score   = result.get("score", 0)
        conf    = result.get("confidence", 0.0)
        attack  = result.get("attack_type", "Unknown")

        def _update_labels():
            self.verdict_var.set(verdict)
            self.verdict_label.configure(fg=VERDICT_COLORS.get(verdict, "black"))
            self.score_var.set(f"{score} / 100")
            self.confidence_var.set(f"{conf}%")
            self.attack_var.set(attack)

        self.root.after(0, _update_labels)

        self.print_to_console("")
        self.print_to_console("=" * 50)
        self.print_to_console(f"  Verdict    : {verdict}")
        self.print_to_console(f"  Score      : {score} / 100")
        self.print_to_console(f"  Confidence : {conf}%")
        self.print_to_console(f"  Attack     : {attack}")
        self.print_to_console("=" * 50)

        # QR-specific info
        qr_url = result.get("qr_decoded_url")
        if qr_url:
            self.print_to_console(f"  QR URL     : {qr_url}")

        for log in result.get("logs", []):
            self.print_to_console(log)

        findings = result.get("findings", [])
        if findings:
            self.print_to_console("")
            self.print_to_console("--- Findings ---")
            for f in findings:
                self.print_to_console(f"  - {f}")

        recs = result.get("recommendation", [])
        if recs:
            self.print_to_console("")
            self.print_to_console("--- Recommendations ---")
            for r in recs:
                self.print_to_console(f"  > {r}")

    # -------------------------------------------------- #
    #  Analysis
    # -------------------------------------------------- #

    def execute_analysis(self):
        if not BACKEND_ONLINE:
            messagebox.showerror("Backend Offline", "Backend modules could not be loaded.")
            return

        data = self.target_input.get("1.0", tk.END).strip()
        if not data:
            messagebox.showwarning("Input Required", "Please enter a URL, message, or file path.")
            return

        scan_type = self.input_type.get()

        if scan_type == "QR Code" and not QR_ONLINE:
            messagebox.showerror("QR Scanner Offline", "qr_scanner.py could not be loaded.\nMake sure OpenCV is installed: pip install opencv-python")
            return

        self._clear_outputs()

        self.print_to_console(f"[+] Input Type : {scan_type}")
        self.print_to_console(f"[+] Target     : {data[:80]}{'...' if len(data) > 80 else ''}")
        self.print_to_console("[+] Running analysis...\n")

        threading.Thread(
            target=self._run_analysis,
            args=(data,),
            daemon=True
        ).start()

    def _run_analysis(self, data: str):
        try:
            scan_type = self.input_type.get()

            if scan_type == "URL":
                result = analyze_url(data)
                is_qr  = False
            elif scan_type == "Email":
                result = analyze_email(data)
                is_qr  = False
            elif scan_type == "SMS":
                result = analyze_sms(data)
                is_qr  = False
            elif scan_type == "QR Code":
                self.print_to_console("[QR] Decoding QR code image...")
                result = scan_qr_for_phishing(data)
                is_qr  = True
            else:  # File Path
                result = analyze_file(data)
                is_qr  = False

            self._result_data = result

            self._show_result(result)
            self._show_pipeline(include_qr=is_qr)

            try:
                self.last_pdf_path = REPORTER_ENGINE.generate(result)
                self.print_to_console(f"\n[OK] Report saved: {self.last_pdf_path}")
            except Exception as e:
                self.print_to_console(f"[!]  Report generation failed: {e}")

        except Exception as e:
            self.root.after(
                0,
                lambda: messagebox.showerror("Analysis Error", str(e))
            )

    # -------------------------------------------------- #
    #  Utilities
    # -------------------------------------------------- #

    def _clear_outputs(self):
        """Clear console and pipeline panels only — keep input intact."""
        for widget in (self.console, self.backend_panel):
            widget.configure(state="normal")
            widget.delete("1.0", tk.END)
            widget.configure(state="disabled")

        def _reset_labels():
            self.verdict_var.set("—")
            self.score_var.set("—")
            self.confidence_var.set("—")
            self.attack_var.set("—")
            self.verdict_label.configure(fg="black")

        self.root.after(0, _reset_labels)

    def clear_workspace(self):
        """Full reset — clears input field and all output panels."""
        self._clear_outputs()
        self.target_input.delete("1.0", tk.END)
        self.last_pdf_path = None
        self._result_data  = None

    def open_pdf(self):
        """Open the last generated PDF report."""
        if self.last_pdf_path:
            from reporter import ForensicReportGenerator
            ForensicReportGenerator.open_report(self.last_pdf_path)
        else:
            messagebox.showinfo("No Report", "Run an analysis first to generate a report.")


# -------------------------------------------------- #
#  Entry point
# -------------------------------------------------- #

if __name__ == "__main__":
    root = tk.Tk()
    app  = PhishGuardApp(root)
    root.mainloop()