import tkinter as tk
from tkinter import messagebox
from rsa import generate_keys, encrypt_oaep

class RSAOAEPGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA-OAEP Encryption GUI")

        self.label = tk.Label(root, text="Masukkan pesan:")
        self.label.pack(pady=5)

        self.entry = tk.Entry(root, width=50)
        self.entry.pack(pady=5)

        self.encrypt_button = tk.Button(root, text="Enkripsi", command=self.encrypt_message)
        self.encrypt_button.pack(pady=10)

        self.result_label = tk.Label(root, text="Ciphertext:")
        self.result_label.pack(pady=5)

        self.result_text = tk.Text(root, height=5, width=60)
        self.result_text.pack(pady=5)

        self.public_key, self.private_key = generate_keys(256)  # Ukuran lebih kecil untuk demo GUI

    def encrypt_message(self):
        message = self.entry.get()
        if not message:
            messagebox.showwarning("Peringatan", "Pesan tidak boleh kosong.")
            return

        try:
            ciphertext = encrypt_oaep(message, self.public_key)
            self.result_text.delete("1.0", tk.END)
            self.result_text.insert(tk.END, str(ciphertext))
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = RSAOAEPGUI(root)
    root.mainloop()
