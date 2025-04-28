import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from decrypt_file import decrypt_file
import os
import rsa 
import hashlib
import sys

class RSAOAEPGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA-OAEP Cryptography Tool")
        self.root.geometry("650x450")
        self.root.resizable(True, True)
        
        # Create notebook (tabbed interface)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True)
        
        # Create encrypt tab
        self.encrypt_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.encrypt_tab, text="Encryption")
        
        # Create decrypt tab
        self.decrypt_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.decrypt_tab, text="Decryption")
        
        # Create key generation tab
        self.keygen_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.keygen_tab, text="Key Generation")
        
        # Setup all tabs
        self.setup_encrypt_tab()
        self.setup_decrypt_tab()
        self.setup_keygen_tab()
    
    def setup_encrypt_tab(self):
        # Create frame for the main content
        main_frame = ttk.Frame(self.encrypt_tab, padding="10")
        main_frame.pack(fill='both', expand=True)
        
        # Create a frame for encryption
        frame = ttk.LabelFrame(main_frame, text="File Encryption")
        frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Input file selection
        ttk.Label(frame, text="Input File:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.encrypt_input_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.encrypt_input_var, width=50).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(frame, text="Browse", command=self.browse_encrypt_input).grid(row=0, column=2, padx=5, pady=5)
        
        # Output file selection
        ttk.Label(frame, text="Output File:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.encrypt_output_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.encrypt_output_var, width=50).grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(frame, text="Browse", command=self.browse_encrypt_output).grid(row=1, column=2, padx=5, pady=5)
        
        # Public key file selection
        ttk.Label(frame, text="Public Key File:").grid(row=2, column=0, sticky='w', padx=5, pady=5)
        self.public_key_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.public_key_var, width=50).grid(row=2, column=1, padx=5, pady=5)
        ttk.Button(frame, text="Browse", command=self.browse_public_key).grid(row=2, column=2, padx=5, pady=5)
        
        # Status label
        self.encrypt_status_var = tk.StringVar()
        self.encrypt_status_var.set("Ready")
        ttk.Label(frame, textvariable=self.encrypt_status_var, font=("", 10)).grid(row=3, column=0, columnspan=3, pady=5)
        
        # Error details label
        self.encrypt_error_var = tk.StringVar()
        ttk.Label(frame, textvariable=self.encrypt_error_var, wraplength=550, foreground="red").grid(row=4, column=0, columnspan=3, pady=5)
        
        # Encrypt button
        ttk.Button(frame, text="Encrypt", command=self.perform_encryption).grid(row=5, column=1, padx=5, pady=10)
    
    def setup_decrypt_tab(self):
        # Create frame for the main content
        main_frame = ttk.Frame(self.decrypt_tab, padding="10")
        main_frame.pack(fill='both', expand=True)
        
        # Create a frame for decryption
        frame = ttk.LabelFrame(main_frame, text="File Decryption")
        frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Ciphertext file selection
        ttk.Label(frame, text="Ciphertext File:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.decrypt_input_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.decrypt_input_var, width=50).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(frame, text="Browse", command=self.browse_decrypt_input).grid(row=0, column=2, padx=5, pady=5)
        
        # Private key file selection
        ttk.Label(frame, text="Private Key File:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.private_key_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.private_key_var, width=50).grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(frame, text="Browse", command=self.browse_private_key).grid(row=1, column=2, padx=5, pady=5)
        
        # Status label
        self.decrypt_status_var = tk.StringVar()
        self.decrypt_status_var.set("Ready")
        ttk.Label(frame, textvariable=self.decrypt_status_var, font=("", 10)).grid(row=2, column=0, columnspan=3, pady=5)
        
        # Error details label
        self.decrypt_error_var = tk.StringVar()
        ttk.Label(frame, textvariable=self.decrypt_error_var, wraplength=550, foreground="red").grid(row=3, column=0, columnspan=3, pady=5)
        
        # Decrypt button
        ttk.Button(frame, text="Decrypt", command=self.perform_decryption).grid(row=4, column=1, padx=5, pady=10)
    
    def setup_keygen_tab(self):
        # Header label
        header_label = tk.Label(self.keygen_tab, text="RSA 2048-bit Key Pair Generator", font=("Arial", 14, "bold"))
        header_label.pack(pady=15)
        
        # Frame for output location
        output_frame = tk.Frame(self.keygen_tab)
        output_frame.pack(pady=10, fill='x')
        
        output_label = tk.Label(output_frame, text="Save Location:")
        output_label.pack(side='left', padx=10)
        
        self.output_var = tk.StringVar(value="./")
        output_entry = tk.Entry(output_frame, textvariable=self.output_var, width=30)
        output_entry.pack(side='left', padx=5)
        
        browse_button = tk.Button(output_frame, text="Browse", command=self.browse_directory)
        browse_button.pack(side='left', padx=5)
        
        # Button "Generate"
        self.generate_button = tk.Button(self.keygen_tab, text="Generate Key Pair", 
                                    command=self.generate_keys,
                                    bg="#4CAF50", fg="white",
                                    font=("Arial", 12),
                                    padx=10, pady=5)
        self.generate_button.pack(pady=20)
        
        # Status display
        status_label = tk.Label(self.keygen_tab, text="Status:")
        status_label.pack(anchor='w', padx=10)
        
        self.status_text = tk.Text(self.keygen_tab, height=10, width=50)
        self.status_text.pack(padx=10, pady=5, fill='both', expand=True)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.keygen_tab, variable=self.progress_var)
        self.progress_bar.pack(fill='x', padx=10, pady=10)
    
    # Encryption tab methods
    def browse_encrypt_input(self):
        filename = filedialog.askopenfilename(title="Select Input File")
        if filename:
            self.encrypt_input_var.set(filename)
            # Auto-generate output filename
            output_filename = filename + ".enc"
            self.encrypt_output_var.set(output_filename)
    
    def browse_encrypt_output(self):
        filename = filedialog.asksaveasfilename(title="Save Encrypted File As")
        if filename:
            self.encrypt_output_var.set(filename)
    
    def browse_public_key(self):
        filename = filedialog.askopenfilename(title="Select Public Key File")
        if filename:
            self.public_key_var.set(filename)
    
    def load_key(self, path):
        """Load a key from a file"""
        hex_part, hex_mod = open(path).read().strip().split(":")
        return int(hex_part, 16), int(hex_mod, 16)
    
    def chunk_data(self, data, k):
        """Split data into chunks for encryption"""
        hLen = hashlib.sha256().digest_size
        m_max = k - 2*hLen - 2
        for i in range(0, len(data), m_max):
            yield data[i: i + m_max]
    
    def perform_encryption(self):
        self.encrypt_status_var.set("Processing...")
        self.encrypt_error_var.set("")
        self.root.update()
        
        input_file = self.encrypt_input_var.get()
        output_file = self.encrypt_output_var.get()
        public_key_file = self.public_key_var.get()
        
        if not input_file or not output_file or not public_key_file:
            messagebox.showerror("Error", "Please select all required files")
            self.encrypt_status_var.set("Ready")
            return
        
        try:
            # Load public key
            e, n = self.load_key(public_key_file)
            k = (n.bit_length() + 7) // 8
            
            # Read input file and write encrypted data to output file
            with open(input_file, "rb") as f_in, open(output_file, "wb") as f_out:
                for block in self.chunk_data(f_in.read(), k):
                    em = rsa.oaep_encode(block, k, hash_func=hashlib.sha256)
                    c_int = pow(int.from_bytes(em, "big"), e, n)
                    f_out.write(c_int.to_bytes(k, "big"))
            
            self.encrypt_status_var.set(f"Encryption successful: {input_file} → {output_file}")
            messagebox.showinfo("Success", "File encryption completed successfully!")
            
        except Exception as e:
            self.encrypt_error_var.set(f"Error: {str(e)}")
            self.encrypt_status_var.set("Encryption failed")
    
    # Decrypt tab methods
    def browse_decrypt_input(self):
        filename = filedialog.askopenfilename(title="Select Ciphertext File")
        if filename:
            self.decrypt_input_var.set(filename)
    
    def browse_private_key(self):
        filename = filedialog.askopenfilename(title="Select Private Key File")
        if filename:
            self.private_key_var.set(filename)
    
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
        self.decrypt_status_var.set("Processing...")
        self.decrypt_error_var.set("")
        self.root.update()
        
        ciphertext_file = self.decrypt_input_var.get()
        private_key_file = self.private_key_var.get()
        
        if not ciphertext_file or not private_key_file:
            messagebox.showerror("Error", "Please select all required files")
            self.decrypt_status_var.set("Ready")
            return
        
        try:
            output_file = self.generate_output_filename(ciphertext_file)
            decrypted_data = decrypt_file(ciphertext_file, output_file, private_key_file)
            
            self.decrypt_status_var.set("Decryption successful")
            messagebox.showinfo("Success", f"File decryption completed successfully!\nSaved to: {output_file}")
        except Exception as e:
            self.decrypt_error_var.set(f"Error: {str(e)}")
            self.decrypt_status_var.set("Decryption failed")
    
    # Key Generation tab methods
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
            
            # 2048-bit key size as per the assignment description
            key_size = 2048
            self.update_status(f"Generating {key_size}-bit RSA key pair...\nThis may take some time.")
            self.progress_var.set(20)
            
            # Generate RSA key pair
            public_key, private_key = rsa.generate_keypair(key_size)
            self.progress_var.set(60)
            
            # Convert keys to hexadecimal format
            public_key_hex = rsa.convert_to_hex(public_key)
            private_key_hex = rsa.convert_to_hex(private_key)
            self.progress_var.set(80)
            
            # Set output file paths
            output_dir = self.output_var.get()
            if output_dir and not output_dir.endswith(('/', '\\')):
                output_dir += '/'
                
            pubkey_path = f"{output_dir}public_key.txt"
            privkey_path = f"{output_dir}private_key.txt"
            
            # Save keys to files
            rsa.save_to_file(public_key_hex, pubkey_path)
            rsa.save_to_file(private_key_hex, privkey_path)
            self.progress_var.set(100)
            
            # Success message
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

if __name__ == "__main__":
    root = tk.Tk()
    app = RSAOAEPGUI(root)
    root.mainloop()