# client_window.py (usa pty para simular o terminal e conseguir tratar inputs)
import tkinter as tk
from tkinter import ttk, scrolledtext
import subprocess
import threading
import sys
import os
import signal

def open_client_window():
    win = tk.Toplevel()
    win.title("Cliente - ChatWithBackdoor")
    win.geometry("900x700")

    text_area = scrolledtext.ScrolledText(win, wrap="word")
    text_area.pack(expand=True, fill="both", padx=5, pady=5)

    bottom = ttk.Frame(win)
    bottom.pack(fill="x", padx=5, pady=5)

    entry = ttk.Entry(bottom)
    entry.pack(side="left", fill="x", expand=True, padx=5)

    master_fd, slave_fd = os.openpty()

    process = subprocess.Popen(
        [sys.executable, "-u", "client.py"],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        close_fds=True,
        bufsize=0,
        preexec_fn=os.setsid
    )

    os.close(slave_fd)

    running = True

    def reader():
        nonlocal running
        try:
            while running:
                try:
                    data = os.read(master_fd, 1024)
                except OSError:
                    break
                if not data:
                    break
                try:
                    text = data.decode("utf-8", errors="replace")
                except Exception:
                    text = repr(data)
                text_area.insert("end", text)
                text_area.see("end")
        finally:
            running = False

    t = threading.Thread(target=reader, daemon=True)
    t.start()

    def send_input(event=None):
        line = entry.get()
        to_send = line + "\n"
        try:
            os.write(master_fd, to_send.encode("utf-8"))
        except Exception:
            pass
        entry.delete(0, "end")

    entry.bind("<Return>", send_input)

    btn = ttk.Button(bottom, text="Enviar", command=send_input)
    btn.pack(side="right", padx=5)

    def on_close():
        nonlocal running
        running = False
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        except Exception:
            try:
                process.terminate()
            except Exception:
                pass
        try:
            process.wait(timeout=2)
        except Exception:
            try:
                process.kill()
            except Exception:
                pass
        try:
            os.close(master_fd)
        except Exception:
            pass
        win.destroy()

    win.protocol("WM_DELETE_WINDOW", on_close)