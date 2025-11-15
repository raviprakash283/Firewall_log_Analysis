import customtkinter as ctk
from tkinter import filedialog, messagebox
import threading
from firewall_analyzer import FirewallAnalyzer


class FirewallGUI(ctk.CTk):

    def __init__(self):
        super().__init__()

        self.title("Firewall Log Analyzer - Cyber Security Toolkit")
        self.geometry("650x420")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.file_path = None

        # Title Label
        self.title_label = ctk.CTkLabel(
            self,
            text="Firewall Log Analyzer",
            font=("Arial", 24, "bold")
        )
        self.title_label.pack(pady=15)

        # File selection
        self.file_label = ctk.CTkLabel(self, text="No file selected", font=("Arial", 14))
        self.file_label.pack(pady=10)

        self.browse_button = ctk.CTkButton(
            self, text="Select Log File", command=self.select_file
        )
        self.browse_button.pack(pady=10)

        # Run Button
        self.run_button = ctk.CTkButton(
            self, text="Run Analysis", fg_color="#1b8c24",
            command=self.start_analysis
        )
        self.run_button.pack(pady=15)

        # Progress Bar
        self.progress = ctk.CTkProgressBar(self, width=400)
        self.progress.set(0)
        self.progress.pack(pady=15)

        # Status Box
        self.status_box = ctk.CTkTextbox(self, width=500, height=120)
        self.status_box.pack(pady=10)

    def log(self, text):
        self.status_box.insert("end", f"[+] {text}\n")
        self.status_box.see("end")

    def select_file(self):
        path = filedialog.askopenfilename(
            title="Select Firewall Log File",
            filetypes=[("Log or CSV Files", "*.log *.txt *.csv")]
        )
        if path:
            self.file_path = path
            self.file_label.configure(text=f"Selected: {path}")

    def start_analysis(self):
        if not self.file_path:
            messagebox.showerror("Error", "No log file selected!")
            return

        threading.Thread(target=self.run_analysis, daemon=True).start()

    def run_analysis(self):
        try:
            self.log("Starting analysis...")

            self.progress.set(0.2)

            analyzer = FirewallAnalyzer(self.file_path)
            analyzer.parse_log()

            self.progress.set(0.6)
            self.log("Running detection rules and threat lookup...")

            analyzer.export_results()

            self.progress.set(1)
            self.log("Analysis completed! Results saved in 'output/' folder.")
            messagebox.showinfo("Done", "Analysis Completed Successfully!")

        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.log(f"Error: {e}")


if __name__ == "__main__":
    app = FirewallGUI()
    app.mainloop()
