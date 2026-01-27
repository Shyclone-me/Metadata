import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
from utils import hash_file, pretty_print_dict, export_to_json
from readers import read_metadata, get_file_type
from editors import edit_file, remove_metadata, add_fake_metadata
from forensics import detect_suspicious, compare_metadata

class MetaShieldGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("MetaShield – Single File Metadata Tool")
        self.geometry("900x700")
        self.current_file = None

        # === Shared Preview Area (top) ===
        preview_frame = tk.LabelFrame(self, text="Metadata Preview (auto-updates when file selected)", padx=10, pady=10)
        preview_frame.pack(fill=tk.BOTH, expand=False, padx=10, pady=5)

        self.preview_text = scrolledtext.ScrolledText(preview_frame, wrap=tk.WORD, height=12, state='disabled')
        self.preview_text.pack(fill=tk.BOTH, expand=True)

        self.preview_text.tag_config('title', foreground='blue', font=('Helvetica', 11, 'bold'))
        self.preview_text.tag_config('error', foreground='red')

        # Output area (for operation results)
        result_frame = tk.LabelFrame(self, text="Operation Result", padx=10, pady=10)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.output_text = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD, height=15)
        self.output_text.pack(fill=tk.BOTH, expand=True)

        self.output_text.tag_config('red', foreground='red')
        self.output_text.tag_config('green', foreground='green')
        self.output_text.tag_config('yellow', foreground='orange')
        self.output_text.tag_config('blue', foreground='blue')

        # Tabs
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=False, padx=10, pady=5)

        self.setup_read_tab(notebook)
        self.setup_edit_tab(notebook)
        self.setup_strip_tab(notebook)
        self.setup_detect_tab(notebook)
        self.setup_compare_tab(notebook)

    def clear_preview(self):
        self.preview_text.configure(state='normal')
        self.preview_text.delete(1.0, tk.END)
        self.preview_text.configure(state='disabled')

    def show_preview(self, file_path):
        self.clear_preview()
        self.preview_text.configure(state='normal')
        try:
            if get_file_type(file_path) is None:
                self.preview_text.insert(tk.END, f"Unsupported file type: {os.path.basename(file_path)}\n", 'error')
            else:
                metadata = read_metadata(file_path)
                self.preview_text.insert(tk.END, f"Metadata for: {os.path.basename(file_path)}\n\n", 'title')
                self.preview_text.insert(tk.END, pretty_print_dict(metadata))
        except Exception as e:
            self.preview_text.insert(tk.END, f"Error reading metadata:\n{str(e)}\n", 'error')
        self.preview_text.configure(state='disabled')

    def clear_output(self):
        self.output_text.delete(1.0, tk.END)

    def insert_output(self, text, tag=None):
        self.output_text.insert(tk.END, text + '\n', tag)
        self.output_text.see(tk.END)

    def update_file(self, path):
        if not path or not os.path.isfile(path):
            self.current_file = None
            self.clear_preview()
            self.insert_output("No valid file selected.", 'red')
            return False

        self.current_file = path
        self.show_preview(path)
        self.clear_output()
        self.insert_output(f"Selected file: {os.path.basename(path)}", 'blue')
        return True

    # ──────────────────────────────────────────────
    # Read Tab
    # ──────────────────────────────────────────────
    def setup_read_tab(self, notebook):
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="Read / Preview")

        tk.Label(tab, text="File:").grid(row=0, column=0, padx=5, pady=8, sticky="e")
        self.read_path = tk.Entry(tab, width=60)
        self.read_path.grid(row=0, column=1, padx=5, pady=8, sticky="ew")
        tk.Button(tab, text="Browse File", command=self.browse_read).grid(row=0, column=2, padx=5)

        tk.Button(tab, text="Export to JSON", command=self.run_export_json).grid(row=1, column=1, pady=10, sticky="w")

        tab.columnconfigure(1, weight=1)

    def browse_read(self):
        path = filedialog.askopenfilename(title="Select File")
        if path:
            self.read_path.delete(0, tk.END)
            self.read_path.insert(0, path)
            self.update_file(path)

    def run_export_json(self):
        if not self.current_file:
            messagebox.showwarning("No File", "Please select a file first.")
            return
        json_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            title="Save Metadata as JSON"
        )
        if json_path:
            try:
                metadata = read_metadata(self.current_file)
                export_to_json(metadata, json_path)
                self.insert_output(f"Metadata exported to: {json_path}", 'green')
            except Exception as e:
                self.insert_output(f"Export failed: {e}", 'red')

    # ──────────────────────────────────────────────
    # Edit Tab
    # ──────────────────────────────────────────────
    def setup_edit_tab(self, notebook):
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="Edit")

        tk.Label(tab, text="File:").grid(row=0, column=0, padx=5, pady=8, sticky="e")
        self.edit_path = tk.Entry(tab, width=60)
        self.edit_path.grid(row=0, column=1, padx=5, pady=8, sticky="ew")
        tk.Button(tab, text="Browse File", command=self.browse_edit).grid(row=0, column=2, padx=5)

        # Remove options
        self.edit_remove_gps     = tk.BooleanVar(value=False)
        self.edit_remove_device  = tk.BooleanVar(value=False)
        self.edit_remove_author  = tk.BooleanVar(value=False)

        tk.Checkbutton(tab, text="Remove GPS", variable=self.edit_remove_gps).grid(row=1, column=0, sticky="w", padx=20)
        tk.Checkbutton(tab, text="Remove Device Info", variable=self.edit_remove_device).grid(row=1, column=1, sticky="w")
        tk.Checkbutton(tab, text="Remove Author", variable=self.edit_remove_author).grid(row=1, column=2, sticky="w")

        # Set new values
        row = 2
        entries = [
            ("Set Author:",   "edit_set_author"),
            ("Set Title:",    "edit_set_title"),
            ("Set Comment:",  "edit_set_comment"),
            ("Set Software:", "edit_set_software"),
        ]
        for label_text, attr in entries:
            tk.Label(tab, text=label_text).grid(row=row, column=0, sticky="e", padx=5, pady=4)
            setattr(self, attr, tk.Entry(tab, width=50))
            getattr(self, attr).grid(row=row, column=1, columnspan=2, sticky="ew", padx=5, pady=4)
            row += 1

        tk.Button(tab, text="Apply Edit", command=self.run_edit).grid(row=row, column=1, pady=15, sticky="w")

        tab.columnconfigure(1, weight=1)

    def browse_edit(self):
        path = filedialog.askopenfilename(title="Select File to Edit")
        if path:
            self.edit_path.delete(0, tk.END)
            self.edit_path.insert(0, path)
            self.update_file(path)

    def run_edit(self):
        if not self.current_file:
            messagebox.showwarning("No File", "Please select a file first.")
            return

        set_author   = self.edit_set_author.get()   or None
        set_title    = self.edit_set_title.get()    or None
        set_comment  = self.edit_set_comment.get()  or None
        set_software = self.edit_set_software.get() or None

        try:
            before = hash_file(self.current_file)
            edit_file(
                self.current_file,
                remove_gps     = self.edit_remove_gps.get(),
                remove_device  = self.edit_remove_device.get(),
                remove_author  = self.edit_remove_author.get(),
                set_author     = set_author,
                set_title      = set_title,
                set_comment    = set_comment,
                set_software   = set_software
            )
            after = hash_file(self.current_file)
            self.insert_output(f"Edit successful: {os.path.basename(self.current_file)}", 'green')
            self.insert_output(f"Hash before: {before}", 'yellow')
            self.insert_output(f"Hash after : {after}", 'yellow')
            # Refresh preview
            self.show_preview(self.current_file)
        except Exception as e:
            self.insert_output(f"Edit failed: {e}", 'red')

    # ──────────────────────────────────────────────
    # Strip Tab (similar pattern)
    # ──────────────────────────────────────────────
    def setup_strip_tab(self, notebook):
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="Strip")

        tk.Label(tab, text="File:").grid(row=0, column=0, padx=5, pady=8, sticky="e")
        self.strip_path = tk.Entry(tab, width=60)
        self.strip_path.grid(row=0, column=1, padx=5, pady=8, sticky="ew")
        tk.Button(tab, text="Browse File", command=self.browse_strip).grid(row=0, column=2, padx=5)

        self.strip_fake = tk.BooleanVar(value=False)
        tk.Checkbutton(tab, text="Add realistic fake metadata after stripping", variable=self.strip_fake).grid(row=1, column=0, columnspan=3, sticky="w", padx=20, pady=8)

        tk.Button(tab, text="Strip Metadata", command=self.run_strip).grid(row=2, column=1, pady=15, sticky="w")

        tab.columnconfigure(1, weight=1)

    def browse_strip(self):
        path = filedialog.askopenfilename(title="Select File to Strip")
        if path:
            self.strip_path.delete(0, tk.END)
            self.strip_path.insert(0, path)
            self.update_file(path)

    def run_strip(self):
        if not self.current_file:
            messagebox.showwarning("No File", "Please select a file first.")
            return

        try:
            before = hash_file(self.current_file)
            remove_metadata(self.current_file)
            if self.strip_fake.get():
                add_fake_metadata(self.current_file)
            after = hash_file(self.current_file)
            action = "Stripped + fake metadata added" if self.strip_fake.get() else "Stripped"
            self.insert_output(f"{action}: {os.path.basename(self.current_file)}", 'green')
            self.insert_output(f"Hash before: {before}", 'yellow')
            self.insert_output(f"Hash after : {after}", 'yellow')
            self.show_preview(self.current_file)
        except Exception as e:
            self.insert_output(f"Strip failed: {e}", 'red')

    # ──────────────────────────────────────────────
    # Detect Tab
    # ──────────────────────────────────────────────
    def setup_detect_tab(self, notebook):
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="Detect Suspicious")

        tk.Label(tab, text="File:").grid(row=0, column=0, padx=5, pady=8, sticky="e")
        self.detect_path = tk.Entry(tab, width=60)
        self.detect_path.grid(row=0, column=1, padx=5, pady=8, sticky="ew")
        tk.Button(tab, text="Browse File", command=self.browse_detect).grid(row=0, column=2, padx=5)

        tk.Button(tab, text="Run Detection", command=self.run_detect).grid(row=1, column=1, pady=15, sticky="w")

        tab.columnconfigure(1, weight=1)

    def browse_detect(self):
        path = filedialog.askopenfilename(title="Select File to Analyze")
        if path:
            self.detect_path.delete(0, tk.END)
            self.detect_path.insert(0, path)
            self.update_file(path)

    def run_detect(self):
        if not self.current_file:
            messagebox.showwarning("No File", "Please select a file first.")
            return

        try:
            susp = detect_suspicious(self.current_file)
            self.insert_output(f"Detection results for {os.path.basename(self.current_file)}:", 'blue')
            if susp:
                for item in susp:
                    self.insert_output("→ " + item, 'red')
            else:
                self.insert_output("No suspicious metadata found.", 'green')
        except Exception as e:
            self.insert_output(f"Detection failed: {e}", 'red')

    # ──────────────────────────────────────────────
    # Compare Tab (unchanged logic, but single file focus)
    # ──────────────────────   ──  ─  ───  ──  ─
    def setup_compare_tab(self, notebook):
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="Compare")

        tk.Label(tab, text="Original File:").grid(row=0, column=0, padx=5, pady=8, sticky="e")
        self.compare_file1 = tk.Entry(tab, width=60)
        self.compare_file1.grid(row=0, column=1, padx=5, pady=8, sticky="ew")
        tk.Button(tab, text="Browse", command=lambda: self.compare_file1.insert(0, filedialog.askopenfilename(title="Select Original File"))).grid(row=0, column=2, padx=5)

        tk.Label(tab, text="Modified File:").grid(row=1, column=0, padx=5, pady=8, sticky="e")
        self.compare_file2 = tk.Entry(tab, width=60)
        self.compare_file2.grid(row=1, column=1, padx=5, pady=8, sticky="ew")
        tk.Button(tab, text="Browse", command=lambda: self.compare_file2.insert(0, filedialog.askopenfilename(title="Select Modified File"))).grid(row=1, column=2, padx=5)

        tk.Button(tab, text="Compare Metadata", command=self.run_compare).grid(row=2, column=1, pady=15, sticky="w")

        tab.columnconfigure(1, weight=1)

    def run_compare(self):
        f1 = self.compare_file1.get().strip()
        f2 = self.compare_file2.get().strip()
        if not f1 or not f2 or not os.path.isfile(f1) or not os.path.isfile(f2):
            messagebox.showerror("Error", "Please select two valid files.")
            return

        self.clear_output()
        try:
            added, removed, changed = compare_metadata(f1, f2)
            self.insert_output(f"Comparison: {os.path.basename(f1)} vs {os.path.basename(f2)}", 'blue')
            if added:
                self.insert_output("Added keys:", 'green')
                for k in sorted(added): self.insert_output("  " + k)
            if removed:
                self.insert_output("Removed keys:", 'red')
                for k in sorted(removed): self.insert_output("  " + k)
            if changed:
                self.insert_output("Changed keys:", 'yellow')
                for k in sorted(changed): self.insert_output("  " + k)
            if not (added or removed or changed):
                self.insert_output("No differences found.", 'green')
        except Exception as e:
            self.insert_output(f"Compare failed: {e}", 'red')


if __name__ == '__main__':
    app = MetaShieldGUI()
    app.mainloop()