import tkinter as tk
from tkinter import ttk, messagebox
import iptc
import json
import os
import ipaddress

RULES_FILE = "rules.json"

# ---------------- WINDOW CENTER ----------------
def center_window(root, width=1000, height=550):
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = int((screen_width / 2) - (width / 2))
    y = int((screen_height / 2) - (height / 2))
    root.geometry(f"{width}x{height}+{x}+{y}")

# ---------------- VALIDATION ----------------
def validate_ip(ip):
    if ip == "ANY":
        return True
    try:
        ipaddress.ip_network(ip, strict=False)
        return True
    except:
        return False

def validate_port(port, protocol):
    if protocol in ["ICMP", "ALL"]:
        return True
    try:
        port = int(port)
        return 0 <= port <= 65535
    except:
        return False

# ---------------- LOAD ----------------
def load_rules():
    if not os.path.exists(RULES_FILE):
        return []
    with open(RULES_FILE) as f:
        return json.load(f)

# ---------------- SAVE ----------------
def save_rules(rules):
    for i, r in enumerate(rules):
        r["position"] = i
    with open(RULES_FILE, "w") as f:
        json.dump(rules, f, indent=4)

# ---------------- APPLY RULES ----------------
def apply_all_rules():
    rules = load_rules()

    table = iptc.Table(iptc.Table.FILTER)
    table.refresh()

    input_chain = iptc.Chain(table, "INPUT")
    output_chain = iptc.Chain(table, "OUTPUT")

    # Safe clear
    for r in list(input_chain.rules):
        try: input_chain.delete_rule(r)
        except: pass

    for r in list(output_chain.rules):
        try: output_chain.delete_rule(r)
        except: pass

    for r in rules:
        chain = iptc.Chain(table, r["direction"])
        rule = iptc.Rule()

        if r["src"] != "ANY":
            rule.src = r["src"]
        if r["dst"] != "ANY":
            rule.dst = r["dst"]

        proto = r["protocol"].lower()

        if proto != "all":
            rule.protocol = proto

        if proto in ["tcp","udp"]:
            match = rule.create_match(proto)
            match.dport = str(r["port"])

        elif proto == "icmp":
            match = rule.create_match("icmp")
            match.icmp_type = "echo-request"

        rule.target = iptc.Target(rule, r["action"])
        chain.insert_rule(rule)

# ---------------- DUPLICATE ----------------
def is_duplicate(new_rule, rules):
    return new_rule in rules

# ---------------- ADD ----------------
def add_rule():
    rules = load_rules()

    src_val = src.get().strip().upper()
    dst_val = dst.get().strip().upper()
    port_val = port.get().strip()

    # Default ANY
    if src_val == "":
        src_val = "ANY"
    if dst_val == "":
        dst_val = "ANY"

    # Validation
    if not validate_ip(src_val):
        messagebox.showerror("Error", "Invalid Source IP")
        return

    if not validate_ip(dst_val):
        messagebox.showerror("Error", "Invalid Destination IP")
        return

    if not validate_port(port_val, protocol.get()):
        messagebox.showerror("Error", "Invalid Port (0-65535)")
        return

    new_rule = {
        "position": len(rules),
        "direction": direction.get(),
        "src": src_val,
        "dst": dst_val,
        "port": int(port_val) if protocol.get() not in ["ICMP","ALL"] else 0,
        "protocol": protocol.get(),
        "action": action.get()
    }

    if is_duplicate(new_rule, rules):
        messagebox.showwarning("Warning", "Rule already exists")
        return

    rules.append(new_rule)
    save_rules(rules)
    apply_all_rules()
    refresh_table()

# ---------------- DELETE ----------------
def delete_rule():
    selected = tree.selection()
    if not selected:
        return

    index = int(tree.item(selected[0])["values"][0])
    rules = load_rules()
    rules.pop(index)

    save_rules(rules)
    apply_all_rules()
    refresh_table()

# ---------------- MOVE ----------------
def move_up():
    selected = tree.selection()
    if not selected:
        return

    index = int(tree.item(selected[0])["values"][0])
    rules = load_rules()

    if index > 0:
        rules[index], rules[index-1] = rules[index-1], rules[index]

    save_rules(rules)
    apply_all_rules()
    refresh_table()

def move_down():
    selected = tree.selection()
    if not selected:
        return

    index = int(tree.item(selected[0])["values"][0])
    rules = load_rules()

    if index < len(rules)-1:
        rules[index], rules[index+1] = rules[index+1], rules[index]

    save_rules(rules)
    apply_all_rules()
    refresh_table()

# ---------------- UI ----------------
root = tk.Tk()
root.title("Firewall Manager")

center_window(root)
root.geometry("790x400")
root.resizable(False, False)

# Handle window close
def on_close():
    print("Closing Firewall Manager...")
    root.destroy()

root.protocol("WM_DELETE_WINDOW", on_close)

# ---------- INPUT ----------
input_frame = tk.Frame(root)
input_frame.pack(fill="x", padx=10, pady=10)

labels = ["Direction", "Source IP", "Destination IP", "Port", "Protocol", "Action"]

for i, text in enumerate(labels):
    tk.Label(input_frame, text=text).grid(row=0, column=i, padx=5, sticky="w")

direction = ttk.Combobox(input_frame, values=["INPUT","OUTPUT"], state="readonly", width=10)
direction.set("OUTPUT")
direction.grid(row=1, column=0, padx=5)

src = tk.Entry(input_frame, width=18)
src.insert(0, "ANY")
src.grid(row=1, column=1, padx=5)

dst = tk.Entry(input_frame, width=18)
dst.insert(0, "ANY")
dst.grid(row=1, column=2, padx=5)

port = tk.Entry(input_frame, width=8)
port.insert(0, "443")
port.grid(row=1, column=3, padx=5)

protocol = ttk.Combobox(input_frame,
                        values=["TCP","UDP","ICMP","ALL"],
                        state="readonly",
                        width=10)
protocol.set("TCP")
protocol.grid(row=1, column=4, padx=5)

action = ttk.Combobox(input_frame,
                      values=["ACCEPT","DROP","REJECT"],
                      state="readonly",
                      width=10)
action.set("DROP")
action.grid(row=1, column=5, padx=5)

tk.Button(input_frame, text="Add Rule", command=add_rule, width=12)\
    .grid(row=1, column=6, padx=10)

# ---------- TABLE ----------
columns = ("Pos","Direction","Source","Destination","Port","Protocol","Action")

tree = ttk.Treeview(root, columns=columns, show="headings")

for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=120)

tree.pack(fill="both", expand=True, padx=10, pady=10)

# ---------- BUTTONS ----------
btn_frame = tk.Frame(root)
btn_frame.pack(pady=5)

tk.Button(btn_frame, text="⬆ Up", command=move_up).pack(side="left", padx=5)
tk.Button(btn_frame, text="⬇ Down", command=move_down).pack(side="left", padx=5)
tk.Button(btn_frame, text="❌ Delete", command=delete_rule).pack(side="left", padx=5)

# ---------- REFRESH ----------
def refresh_table():
    for row in tree.get_children():
        tree.delete(row)

    rules = load_rules()

    for r in rules:
        tree.insert("", "end", values=(
            r["position"],
            r["direction"],
            r["src"],
            r["dst"],
            r["port"],
            r["protocol"],
            r["action"]
        ))

# ---------- INIT ----------
if not os.path.exists(RULES_FILE):
    with open(RULES_FILE, "w") as f:
        json.dump([], f)

apply_all_rules()
refresh_table()

# ---------- CLEAN EXIT ----------
try:
    root.mainloop()
except KeyboardInterrupt:
    print("Exiting Firewall Manager...")
    root.destroy()