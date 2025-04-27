import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import rsa

class KeyGenGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA Key Pair Generation GUI")
        self.root.geometry("500x400")

        # Header label
        self.header_label = tk.Label(root, text="RSA 2048-bit Key Pair Generator", font=("Arial", 14, "bold"))
        self.header_label.pack(pady=15)
        
        # Frame untuk lokasi output
        self.output_frame = tk.Frame(root)
        self.output_frame.pack(pady=10, fill='x')
        
        self.output_label = tk.Label(self.output_frame, text="Lokasi penyimpanan:")
        self.output_label.pack(side='left', padx=10)
        
        self.output_var = tk.StringVar(value="./")
        self.output_entry = tk.Entry(self.output_frame, textvariable=self.output_var, width=30)
        self.output_entry.pack(side='left', padx=5)
        
        self.browse_button = tk.Button(self.output_frame, text="Browse", command=self.browse_directory)
        self.browse_button.pack(side='left', padx=5)
        
        # Button "Generate"
        self.generate_button = tk.Button(root, text="Generate Key Pair", 
                                        command=self.generate_keys,
                                        bg="#4CAF50", fg="white",
                                        font=("Arial", 12),
                                        padx=10, pady=5)
        self.generate_button.pack(pady=20)
        
        # Status display
        self.status_label = tk.Label(root, text="Status:")
        self.status_label.pack(anchor='w', padx=10)
        
        self.status_text = tk.Text(root, height=10, width=50)
        self.status_text.pack(padx=10, pady=5, fill='both', expand=True)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(root, variable=self.progress_var)
        self.progress_bar.pack(fill='x', padx=10, pady=10)

    def browse_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.output_var.set(directory)
    
    def update_status(self, message):
        self.status_text.delete("1.0", tk.END)
        self.status_text.insert(tk.END, message)
        self.root.update()
    
    def generate_keys(self):
        try:
            # Disable button while generating
            self.generate_button.config(state='disabled')
            self.progress_var.set(10)
            
            # Panjang key 2048 bit sesuai deskripsi tugas
            key_size = 2048
            self.update_status(f"Generating {key_size}-bit RSA key pair...\nThis may take some time.")
            self.progress_var.set(20)
            
            # Generate RSA key pair
            public_key, private_key = rsa.generate_keypair(key_size)
            self.progress_var.set(60)
            
            # Ubah keys ke dalam bentuk hexadecimal
            public_key_hex = rsa.convert_to_hex(public_key)
            private_key_hex = rsa.convert_to_hex(private_key)
            self.progress_var.set(80)
            
            # Set path file-file output
            output_dir = self.output_var.get()
            if output_dir and not output_dir.endswith(('/', '\\')):
                output_dir += '/'
                
            pubkey_path = f"{output_dir}public_key.txt"
            privkey_path = f"{output_dir}private_key.txt"
            
            # Simpan keys ke dalam file
            rsa.save_to_file(public_key_hex, pubkey_path)
            rsa.save_to_file(private_key_hex, privkey_path)
            self.progress_var.set(100)
            
            # Pesan berhasil!
            success_message = f"RSA Key Pair Generation Successful!\n\n"
            success_message += f"Public Key saved to: {pubkey_path}\n"
            success_message += f"Private Key saved to: {privkey_path}"
            self.update_status(success_message)
            
            messagebox.showinfo("Success", "RSA Key Pair generated successfully!")
            
        except Exception as e:
            self.update_status(f"Error: {str(e)}")
            messagebox.showerror("Error", str(e))
        finally:
            self.generate_button.config(state='normal')

def main():
    root = tk.Tk()
    app = KeyGenGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
