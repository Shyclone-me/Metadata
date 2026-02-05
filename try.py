# Phishing URL Inspector - Student Edition v3.0
# Added features: 3 (emojis in reasons), 5 (timestamps), 8 (batch check), 13 (homoglyph/punycode), 15 (Levenshtein distance)
# Still 100% offline - only built-in modules

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import urllib.parse
import time

# Suspicious patterns (easy to extend)
SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "account", "update", "secure",
    "password", "bank", "free", "prize", "claim", "paypal"
]

SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "is.gd", "ow.ly", "t.co", "buff.ly"]

# Popular domains for Levenshtein check (feature 15) - add more if you want
POPULAR_DOMAINS = ["google.com", "paypal.com", "apple.com", "amazon.com", "facebook.com", "microsoft.com", "bankofamerica.com"]

class PhishingInspector:
    def __init__(self, root):
        self.root = root
        self.root.title("Phishing URL Inspector v3.0")
        self.root.geometry("750x680")
        self.root.resizable(False, False)
        self.root.configure(bg="#f5f7fa")

        self.current_url = ""  # For save
        self.current_verdict = ""
        self.current_score = 0
        self.current_reasons = []
        self.current_timestamp = ""  # For feature 5

        # ── Title ────────────────────────────────────────────────────────
        tk.Label(root, text="Phishing URL Inspector", font=("Helvetica", 18, "bold"),
                 bg="#f5f7fa", fg="#2c3e50").pack(pady=15)

        # ── Input Area (now multi-line for batch - feature 8) ────────────
        input_frame = tk.LabelFrame(root, text=" Enter URLs (one per line for batch) ", bg="#f5f7fa", padx=10, pady=5)
        input_frame.pack(padx=25, pady=10, fill="x")

        self.url_text = scrolledtext.ScrolledText(input_frame, height=4, font=("Helvetica", 11), wrap="word")
        self.url_text.pack(fill="both", expand=True)
        self.url_text.focus()

        # ── Buttons ──────────────────────────────────────────────────────
        btn_frame = tk.Frame(root, bg="#f5f7fa")
        btn_frame.pack(pady=12)

        self.scan_btn = ttk.Button(btn_frame, text="Scan URLs", command=self.start_scan, style="Scan.TButton")
        self.scan_btn.pack(side="left", padx=8)

        ttk.Button(btn_frame, text="Clear", command=self.clear_all).pack(side="left", padx=8)
        ttk.Button(btn_frame, text="Save Result", command=self.save_result).pack(side="left", padx=8)

        # ── Progress / Status ────────────────────────────────────────────
        self.status_label = tk.Label(root, text="Ready", font=("Helvetica", 10), bg="#f5f7fa", fg="#7f8c8d")
        self.status_label.pack(pady=(0,5))

        self.progress = ttk.Progressbar(root, mode='indeterminate', length=400)
        # (packed dynamically)

        # ── Result Area ──────────────────────────────────────────────────
        result_frame = tk.LabelFrame(root, text=" Analysis Result ", bg="white", padx=15, pady=10)
        result_frame.pack(padx=25, pady=10, fill="both", expand=True)

        self.verdict_label = tk.Label(result_frame, text="Waiting...", font=("Helvetica", 20, "bold"),
                                      bg="white", fg="#95a5a6")
        self.verdict_label.pack(pady=15)

        self.score_label = tk.Label(result_frame, text="", font=("Helvetica", 12), bg="white")
        self.score_label.pack()

        # Features summary
        self.features_text = tk.Text(result_frame, height=6, font=("Helvetica", 10), wrap="word",
                                     bg="#f9fbfc", bd=0, highlightthickness=0)
        self.features_text.pack(fill="x", pady=(10,0))

        # Reasons
        tk.Label(result_frame, text="Reasons / Warnings:", font=("Helvetica", 11, "bold"),
                 bg="white").pack(anchor="w", pady=(15,5))

        self.reasons_text = scrolledtext.ScrolledText(result_frame, height=8, font=("Helvetica", 10),
                                                      bg="#f9fbfc", wrap="word")
        self.reasons_text.pack(fill="both", expand=True, pady=(0,10))

        # ── History ──────────────────────────────────────────────────────
        history_frame = tk.LabelFrame(root, text=" Recent Checks ", bg="#f5f7fa", padx=10, pady=5)
        history_frame.pack(padx=25, pady=(0,15), fill="x")

        self.history_list = tk.Listbox(history_frame, height=6, font=("Helvetica", 10), bg="white")
        self.history_list.pack(fill="x")

        # Style
        style = ttk.Style()
        style.configure("Scan.TButton", font=("Helvetica", 11), padding=8)

        self.root.bind("<Return>", lambda e: self.start_scan())

    def start_scan(self):
        urls_input = self.url_text.get("1.0", tk.END).strip()
        if not urls_input:
            messagebox.showwarning("Input Required", "Please enter at least one URL")
            return

        self.current_url = urls_input  # Save all for later

        # Show analyzing
        self.scan_btn.config(state="disabled")
        self.status_label.config(text="Analyzing...", fg="#e67e22")
        self.progress.pack(pady=8)
        self.progress.start(15)

        # Fake delay for progress (real check is fast)
        self.root.after(1200, self.do_scan)  # Longer for batch feel

    def do_scan(self):
        urls_input = self.current_url
        urls = [u.strip() for u in urls_input.splitlines() if u.strip()]  # Split for batch (feature 8)

        all_verdicts = []
        all_scores = []
        all_reasons = []
        all_features = []

        self.current_timestamp = time.strftime("%Y-%m-%d %H:%M:%S")  # Feature 5: timestamp

        for url in urls:
            verdict, color, score, reasons, features = self.analyze_url(url)
            all_verdicts.append(verdict)
            all_scores.append(score)
            all_reasons.extend(reasons)  # Combine for display
            all_features.extend(features)  # Combine

            # History (with time - feature 5)
            short_url = (url[:45] + "...") if len(url) > 45 else url
            history_entry = f"[{self.current_timestamp}] {verdict:<12} | {short_url}"
            self.history_list.insert(0, history_entry)
            if self.history_list.size() > 8:
                self.history_list.delete(8, tk.END)

        # Overall for multi-URL
        avg_score = sum(all_scores) / len(all_scores) if all_scores else 0
        overall_verdict = max(set(all_verdicts), key=all_verdicts.count)  # Most common verdict
        overall_color = "red" if avg_score >= 60 else "#e67e22" if avg_score >= 30 else "#27ae60"

        self.progress.stop()
        self.progress.pack_forget()
        self.scan_btn.config(state="normal")
        self.status_label.config(text="Scan complete", fg="#2ecc71")

        self.verdict_label.config(text=overall_verdict, fg=overall_color)
        self.score_label.config(text=f"Avg Risk Score: {int(avg_score)}/100", fg=overall_color)

        # Features (combined unique)
        self.features_text.delete("1.0", tk.END)
        self.features_text.insert(tk.END, "\n".join(set(all_features)))  # Unique to avoid repeats

        # Reasons (with emojis - feature 3)
        self.reasons_text.delete("1.0", tk.END)
        if all_reasons:
            for r in set(all_reasons):  # Unique
                emoji = "⚠️ " if "suspicious" in r.lower() or "insecure" in r.lower() else "❌ "
                self.reasons_text.insert(tk.END, f"{emoji}{r}\n")
        else:
            self.reasons_text.insert(tk.END, "No strong suspicious signs detected.\n")

        # Save overall
        self.current_verdict = overall_verdict
        self.current_score = int(avg_score)
        self.current_reasons = all_reasons

    def analyze_url(self, url):
        reasons = []
        features = []
        score = 0

        original_url = url
        url = url.lower().strip()

        # Auto-add protocol if missing
        if not url.startswith(('http://', 'https://')):
            check_url = 'http://' + url
        else:
            check_url = url

        # Protocol check
        is_https = original_url.lower().startswith("https://")
        padlock = "🔒 HTTPS" if is_https else "🔓 HTTP"
        features.append(f"Protocol:     {padlock}")
        if not is_https:
            score += 20
            reasons.append("Insecure connection (uses HTTP instead of HTTPS)")

        # Parse
        parsed = urllib.parse.urlparse(check_url)
        host = parsed.hostname or ""
        domain = host.split('.')[-2:] if '.' in host else [host]  # Simple domain extract for checks

        # Basic features
        length = len(check_url)
        features.append(f"Length:       {length} characters")
        if length > 75:
            score += 20
            reasons.append(f"Very long URL ({length} chars)")

        dots = check_url.count('.')
        features.append(f"Dots:         {dots}")
        if dots > 5:
            score += 15
            reasons.append(f"Many dots ({dots}) – possible obfuscation")

        hyphens = check_url.count('-')
        features.append(f"Hyphens:      {hyphens}")
        if hyphens > 4:
            score += 12
            reasons.append(f"Many hyphens ({hyphens})")

        slashes = check_url.count('/')
        features.append(f"Slashes:      {slashes}")
        if slashes > 8:
            score += 12
            reasons.append(f"Many slashes ({slashes})")

        has_at = '@' in check_url
        features.append(f"@ symbol:     {'Yes' if has_at else 'No'}")
        if has_at:
            score += 35
            reasons.append("Contains '@' symbol – classic phishing pattern")

        # IP check
        is_ip = False
        try:
            parts = host.split('.')
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                is_ip = True
        except:
            pass
        features.append(f"IP address:   {'Yes' if is_ip else 'No'}")
        if is_ip:
            score += 40
            reasons.append("Uses raw IP address instead of domain name")

        # Shortener
        is_shortener = any(s in host for s in SHORTENERS)
        features.append(f"Shortener:    {'Yes' if is_shortener else 'No'}")
        if is_shortener:
            score += 25
            reasons.append("Uses known URL shortener service")

        # Keywords
        found = [w for w in SUSPICIOUS_WORDS if w in check_url]
        if found:
            score += len(found) * 12
            reasons.append(f"Suspicious words: {', '.join(found)}")

        # Feature 13: Homoglyph / Punycode detection
        # Simple check: non-ASCII chars or 'xn--' punycode prefix
        has_homoglyph = any(ord(c) > 127 for c in host)  # Non-English chars
        is_punycode = host.startswith('xn--')
        if has_homoglyph or is_punycode:
            score += 30
            reasons.append("Possible homoglyph attack (look-alike characters or punycode domain)")
            features.append(f"Homoglyph:    {'Yes' if has_homoglyph or is_punycode else 'No'}")

        # Feature 15: Levenshtein distance to popular domains
        # Check if domain is close to popular ones (typosquatting)
        main_domain = '.'.join(domain)
        min_distance = float('inf')
        for pop in POPULAR_DOMAINS:
            dist = self.levenshtein_distance(main_domain, pop)
            if dist < min_distance:
                min_distance = dist
        if 0 < min_distance <= 2:  # Close but not exact
            score += 35
            reasons.append(f"Typosquatting detected (close to popular domain, distance {min_distance})")
        features.append(f"Closest popular domain distance: {min_distance}")

        score = min(score, 100)

        if score >= 60:
            verdict = "PHISHING"
            color = "red"
        elif score >= 30:
            verdict = "SUSPICIOUS"
            color = "#e67e22"
        else:
            verdict = "SAFE"
            color = "#27ae60"

        return verdict, color, score, reasons, features

    def levenshtein_distance(self, s1, s2):
        # Simple Levenshtein function (feature 15) - dynamic programming
        # This measures edit distance (insert/delete/substitute)
        if len(s1) < len(s2):
            return self.levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    def clear_all(self):
        self.url_text.delete("1.0", tk.END)
        self.verdict_label.config(text="Waiting...", fg="#95a5a6")
        self.score_label.config(text="")
        self.features_text.delete("1.0", tk.END)
        self.reasons_text.delete("1.0", tk.END)
        self.status_label.config(text="Ready", fg="#7f8c8d")

    def save_result(self):
        if not self.current_url:
            messagebox.showinfo("Nothing to save", "Scan some URLs first.")
            return

        content = f"[{self.current_timestamp}]  # Feature 5: timestamp in save\n"  # Feature 5
        content += f"URLs:\n{self.current_url}\n"
        content += f"Verdict: {self.current_verdict}\n"
        content += f"Risk Score: {self.current_score}/100\n\n"
        content += "Features:\n" + self.features_text.get("1.0", tk.END).strip() + "\n\n"
        content += "Reasons:\n" + self.reasons_text.get("1.0", tk.END).strip() + "\n"
        content += "-" * 60 + "\n"

        try:
            with open("phishing_scan_history.txt", "a", encoding="utf-8") as f:
                f.write(content)
            messagebox.showinfo("Saved", "Result appended to phishing_scan_history.txt")
        except Exception as e:
            messagebox.showerror("Save Error", f"Could not save:\n{str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = PhishingInspector(root)
    root.mainloop()