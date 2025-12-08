import tkinter as tk
from tkinter import ttk
import server_window
import client_window

def open_server():
    server_window.open_server_window()

def open_client():
    client_window.open_client_window()

root = tk.Tk()
root.title("ChatWithBackdoor")
root.geometry("400x200")

frame = ttk.Frame(root, padding=20)
frame.pack(expand=True)

label = ttk.Label(frame, text="Escolha uma opção:")
label.pack(pady=10)

btn_server = ttk.Button(frame, text="Iniciar o servidor", command=open_server)
btn_server.pack(fill="x", pady=10)

btn_client = ttk.Button(frame, text="Entrar como cliente", command=open_client)
btn_client.pack(fill="x", pady=10)

root.mainloop()