import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from decrypt_file import decrypt_file
import os
import ast

# Import the functions from your existing file

class RSAOAEPGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA-OAEP Dekripsi")
        self.root.geometry("600x280")
        self.root.resizable(True, True)
        
        # Create frame for the main content
        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill='both', expand=True)
        
        # Create a frame for decryption
        frame = ttk.LabelFrame(main_frame, text="Dekripsi File")
        frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Ciphertext file selection
        ttk.Label(frame, text="File Ciphertext:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.decrypt_input_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.decrypt_input_var, width=50).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(frame, text="Browse", command=self.browse_decrypt_input).grid(row=0, column=2, padx=5, pady=5)
        
        # Private key file selection
        ttk.Label(frame, text="File Private Key:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.private_key_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.private_key_var, width=50).grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(frame, text="Browse", command=self.browse_private_key).grid(row=1, column=2, padx=5, pady=5)
        
        # Status label
        self.status_var = tk.StringVar()
        self.status_var.set("Siap")
        ttk.Label(frame, textvariable=self.status_var, font=("", 10)).grid(row=2, column=0, columnspan=3, pady=5)
        
        # Error details label
        self.error_var = tk.StringVar()
        ttk.Label(frame, textvariable=self.error_var, wraplength=550, foreground="red").grid(row=3, column=0, columnspan=3, pady=5)
        
        # Decrypt button
        ttk.Button(frame, text="Dekripsi", command=self.perform_decryption).grid(row=4, column=1, padx=5, pady=10)
    
    def browse_decrypt_input(self):
        filename = filedialog.askopenfilename(title="Pilih File Ciphertext")
        if filename:
            self.decrypt_input_var.set(filename)
    
    def browse_private_key(self):
        filename = filedialog.askopenfilename(title="Pilih File Private Key")
        if filename:
            self.private_key_var.set(filename)
    
    def read_private_key(self, key_file_path):
        """Read the private key tuple from a file"""
        try:
            with open(key_file_path, 'r') as f:
                key_content = f.read().strip()
                # Convert string representation of tuple to actual tuple
                return ast.literal_eval(key_content)
        except Exception as e:
            raise ValueError(f"Failed to read private key: {str(e)}")
    
    def read_ciphertext(self, ciphertext_file_path):
        """Read the ciphertext bytes from a file"""
        try:
            with open(ciphertext_file_path, 'rb') as f:  # Mode teks, bukan binary
                text_data = f.read().strip()
                
                return text_data
        except Exception as e:
            raise ValueError(f"Failed to read ciphertext: {str(e)}")
    
    def generate_output_filename(self, input_file):
        """Generate an output filename based on the input file"""
        # Get the directory and base filename
        directory = os.path.dirname(input_file)
        base_name = os.path.basename(input_file)
        
        # Add '_decrypted' suffix before the extension
        name_parts = os.path.splitext(base_name)
        output_filename = name_parts[0] + "_decrypted" + name_parts[1]
        
        # Full path to the output file
        output_path = os.path.join(directory, output_filename)
        
        # If file already exists, add a number suffix
        counter = 1
        while os.path.exists(output_path):
            output_filename = f"{name_parts[0]}_decrypted_{counter}{name_parts[1]}"
            output_path = os.path.join(directory, output_filename)
            counter += 1
            
        return output_path
    
    def write_output(self, output_file_path, decrypted_data):
        """Write the decrypted data to the output file"""
        try:
            with open(output_file_path, 'wb') as f:
                f.write(decrypted_data)
        except Exception as e:
            raise ValueError(f"Failed to write output file: {str(e)}")
    
    def perform_decryption(self):
        self.status_var.set("Memproses...")
        self.error_var.set("")  # Clear any previous error
        self.root.update()
        
        ciphertext_file = self.decrypt_input_var.get()
        private_key_file = self.private_key_var.get()
        
        if not ciphertext_file or not private_key_file:
            messagebox.showerror("Error", "Silakan pilih semua file yang diperlukan")
            self.status_var.set("Siap")
            return
        
        try:
            decrypted_data = decrypt_file(ciphertext_file, "output.txt", private_key_file)
            
            self.status_var.set("Dekripsi berhasil")
        except Exception as e:
            self.error_var.set(f"Error: {str(e)}")
            self.status_var.set("Dekripsi gagal")

if __name__ == "__main__":
    root = tk.Tk()
    app = RSAOAEPGUI(root)
    root.mainloop()