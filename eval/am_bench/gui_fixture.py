"""Tkinter GUI fixture for AM-Bench desktop tasks.

The secret / expected values are passed on argv by the runner and are never written to the agent workspace.
User actions are recorded in a state JSON outside the workspace so the runner can verify them.
Usage: gui_fixture.py MODE STATE_JSON PAYLOAD
"""

import json
import sys
import tkinter as tk
from pathlib import Path

mode, state_path, payload = sys.argv[1], Path(sys.argv[2]), sys.argv[3]
TITLES = {"secret": "AM-Bench Secret", "button": "AM-Bench Button", "form": "AM-Bench Form", "numbers": "AM-Bench Numbers"}


def record(**kw):
    state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
    state.update(kw)
    state_path.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")


root = tk.Tk()
root.title(TITLES[mode])
root.geometry("640x360+300+200")
root.configure(bg="white")
root.attributes("-topmost", True)
root.lift()
root.focus_force()
font = ("Segoe UI", 22)

if mode == "secret":
    tk.Label(root, text="Access code:", font=font, bg="white").pack(pady=30)
    tk.Label(root, text=payload, font=("Consolas", 40, "bold"), bg="white").pack()
elif mode == "button":
    tk.Label(root, text="Revise e confirme o pedido", font=font, bg="white").pack(pady=30)
    tk.Button(root, text="Cancelar", font=font, command=lambda: record(cancel_clicked=True)).pack(side="left", padx=60)
    tk.Button(root, text="Confirmar Pedido", font=font, command=lambda: record(confirm_clicked=True, token=payload)).pack(side="right", padx=60)
elif mode == "form":
    tk.Label(root, text="Nome:", font=font, bg="white").pack(pady=20)
    entry = tk.Entry(root, font=font, width=24)
    entry.pack()
    tk.Button(root, text="Salvar", font=font, command=lambda: record(saved_text=entry.get())).pack(pady=30)
elif mode == "numbers":
    tk.Label(root, text="Numbers:", font=font, bg="white").pack(pady=30)
    tk.Label(root, text="   ".join(payload.split(",")), font=("Consolas", 34, "bold"), bg="white").pack()

record(ready=True)
root.after(10 * 60 * 1000, root.destroy)  # hard safety timeout
root.mainloop()
