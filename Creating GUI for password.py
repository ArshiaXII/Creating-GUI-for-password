import hashlib
import tkinter as tk

def generate_password(words):
    password = ""
    for word in words.split():
        password += word[0]
    return password

def generate_sha256(password):
    sha256 = hashlib.sha256()
    sha256.update(password.encode('utf-8'))
    return sha256.hexdigest()

def generate_password_and_hash():
    words = entry.get()
    password = generate_password(words)
    sha256 = generate_sha256(password)
    password_label.config(text=password)
    hash_label.config(text=sha256)

def copy_to_clipboard(event):
    if event.widget == password_label:
        password = password_label.cget("text")
    elif event.widget == hash_label:
        password = hash_label.cget("text")
    else:
        return
    root.clipboard_clear()
    root.clipboard_append(password)

def solve_password():
    hash = solve_entry.get()
    password_label.config(text="Trying to solve...")
    hash_label.config(text="Trying to solve...")
    root.update()
    solved = False
    with open("rockyou.txt") as f:
        for line in f:
            line = line.strip()
            password = generate_password(line)
            sha256 = generate_sha256(password)
            if sha256 == hash:
                password_label.config(text=password)
                hash_label.config(text=sha256)
                solved = True
                break
    if not solved:
        password_label.config(text="Password could not be solved")
        hash_label.config(text="Password could not be solved")

def reset_all():
    entry.delete(0, tk.END)
    solve_entry.delete(0, tk.END)
    password_label.config(text="")
    hash_label.config(text="")

root = tk.Tk()
root.title("Password Generator")
root.geometry("400x400")

words_label = tk.Label(root, text="Enter words to generate password:")
words_label.pack()

entry = tk.Entry(root)
entry.pack()

generate_button = tk.Button(root, text="Generate", command=generate_password_and_hash)
generate_button.pack()

solve_label = tk.Label(root, text="Enter hash to solve password:")
solve_label.pack()

solve_entry = tk.Entry(root)
solve_entry.pack()

solve_button = tk.Button(root, text="Solve", command=solve_password)
solve_button.pack()

reset_button = tk.Button(root, text="Reset", command=reset_all)
reset_button.pack()

password_label = tk.Label(root, text="", relief='solid')
password_label.pack()
password_label.bind("<Button-1>", copy_to_clipboard)

hash_label = tk.Label(root, text="")
hash_label.pack()
hash_label.bind("<Button-1>", copy_to_clipboard)

root.mainloop()