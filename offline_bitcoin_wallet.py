import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from mnemonic import Mnemonic
from bip32 import BIP32
import binascii

def generate_mnemonic(strength=128):
    mnemo = Mnemonic("english")
    return mnemo.generate(strength=strength)

def create_root_key(mnemonic, passphrase=''):
    seed = Mnemonic.to_seed(mnemonic, passphrase)
    return BIP32.from_seed(seed)

def derive_address(root_key, account=0, change=0, address_index=0):
    path = f"m/44'/0'/{account}'/{change}/{address_index}"
    priv_key = root_key.get_privkey_from_path(path)
    pub_key = root_key.get_pubkey_from_path(path)
    
    priv_key_hex = binascii.hexlify(priv_key).decode('utf-8')
    pub_key_hex = binascii.hexlify(pub_key).decode('utf-8')
    
    return priv_key_hex, pub_key_hex

class OfflineWalletApp:
    def __init__(self, master):
        self.master = master
        master.title("Offline Bitcoin Wallet Generator")

        # Setup frames
        self.setup_frames()

        # Setup widgets
        self.setup_widgets()

    def setup_frames(self):
        self.top_frame = ttk.Frame(self.master)
        self.top_frame.pack(padx=10, pady=5, fill='x', expand=True)

        self.middle_frame = ttk.Frame(self.master)
        self.middle_frame.pack(padx=10, pady=5, fill='x', expand=True)

        self.bottom_frame = ttk.Frame(self.master)
        self.bottom_frame.pack(padx=10, pady=5, fill='x', expand=True)

    def setup_widgets(self):
        # Passphrase entry
        ttk.Label(self.top_frame, text="Enter a secure passphrase (optional):").pack(side='left')
        self.passphrase_entry = ttk.Entry(self.top_frame, show="*")
        self.passphrase_entry.pack(side='left')
        
        # Show/Hide Passphrase Checkbox
        self.show_pass_var = tk.BooleanVar()
        self.show_pass_check = ttk.Checkbutton(self.top_frame, text='Show Passphrase', variable=self.show_pass_var, command=self.toggle_passphrase_visibility)
        self.show_pass_check.pack(side='left')

        # Address count entry
        ttk.Label(self.middle_frame, text="Number of addresses to generate:").pack(side='left')
        self.address_count_entry = ttk.Entry(self.middle_frame)
        self.address_count_entry.pack(side='left')

        # Generate wallet button
        self.generate_button = ttk.Button(self.bottom_frame, text="Generate Wallet", command=self.generate_wallet)
        self.generate_button.pack()

        # Display area for mnemonic and wallet details
        self.wallet_details = tk.Text(self.master, height=20, width=50)
        self.wallet_details.pack(padx=10, pady=5)
        self.wallet_details.config(state=tk.DISABLED)

    def toggle_passphrase_visibility(self):
        if self.show_pass_var.get():
            self.passphrase_entry.config(show="")
        else:
            self.passphrase_entry.config(show="*")

    def generate_wallet(self):
        passphrase = self.passphrase_entry.get()
        address_count = int(self.address_count_entry.get())
        mnemonic = generate_mnemonic()
        root_key = create_root_key(mnemonic, passphrase)
        
        details = f"Mnemonic: {mnemonic}\n\n"
        
        for i in range(address_count):
            priv_key, pub_key = derive_address(root_key, account=0, change=0, address_index=i)
            details += f"Address {i+1} Private Key: {priv_key}\nAddress {i+1} Public Key: {pub_key}\n\n"
        
        self.wallet_details.config(state=tk.NORMAL)
        self.wallet_details.delete('1.0', tk.END)
        self.wallet_details.insert(tk.END, details)
        self.wallet_details.config(state=tk.DISABLED)

def main():
    root = tk.Tk()
    app = OfflineWalletApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
