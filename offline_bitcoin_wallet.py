import tkinter as tk
from tkinter import ttk, messagebox
import qrcode
from PIL import Image, ImageTk
from mnemonic import Mnemonic
from bip32 import BIP32
import binascii
import io
import hashlib
import base58

# Helper function to convert byte data to hex string
def bytes_to_hex(byte_data):
    """Convert byte data to a hex string."""
    return binascii.hexlify(byte_data).decode('utf-8')

def public_key_to_address(public_key_hex):
    # Step 1: SHA-256 hashing on the public key
    sha256 = hashlib.sha256()
    sha256.update(bytes.fromhex(public_key_hex))
    sha_result = sha256.digest()

    # Step 2: RIPEMD-160 hashing on the result of SHA-256
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha_result)
    ripemd_result = ripemd160.digest()

    # Step 3: Adding network byte
    network_byte = b'\x00'
    network_and_ripemd = network_byte + ripemd_result

    # Step 4: Create a checksum
    checksum_full = hashlib.sha256(hashlib.sha256(network_and_ripemd).digest()).digest()
    checksum = checksum_full[:4]

    # Step 5: Concatenate and encode
    binary_address = network_and_ripemd + checksum
    bitcoin_address = base58.b58encode(binary_address)

    return bitcoin_address.decode('utf-8')

# Function to generate a mnemonic
def generate_mnemonic(strength=128):
    """Generate a mnemonic with the specified strength."""
    mnemo = Mnemonic("english")
    return mnemo.generate(strength=strength)

# Function to create a root key from a mnemonic and passphrase
def create_root_key(mnemonic, passphrase=''):
    """Create a root key from the given mnemonic and passphrase."""
    seed = Mnemonic.to_seed(mnemonic, passphrase)
    return BIP32.from_seed(seed)

# Function to derive an address from a root key
def derive_address(root_key, account=0, change=0, address_index=0):
    """Derive a cryptocurrency address from a root key."""
    path = f"m/44'/0'/{account}'/{change}/{address_index}"
    priv_key = root_key.get_privkey_from_path(path)
    pub_key = root_key.get_pubkey_from_path(path)
    
    priv_key_hex = bytes_to_hex(priv_key)
    pub_key_hex = bytes_to_hex(pub_key)
    address = public_key_to_address(pub_key_hex)
    
    return priv_key_hex, pub_key_hex, address

# Function to generate a QR code for a given data string
def generate_qr_code(data):
    """Generate a QR code for the given data."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format='PNG')
    img_byte_arr = img_byte_arr.getvalue()
    return img_byte_arr

class OfflineWalletApp:
    def __init__(self, master):
        """Initialize the Offline Wallet Application."""
        self.master = master
        master.title("Offline Bitcoin Wallet Generator")
        self.setup_layout()
        self.mnemonic = ""
        self.qr_popup = None

    def setup_layout(self):
        """Setup the layout of the application."""
        self.setup_input_frame()
        self.setup_output_frame()
        self.setup_import_mode()
        self.setup_context_menu()  # Setup the context menu for copying

    def setup_input_frame(self):
        """Setup the input frame for mnemonic and passphrase input."""
        input_frame = ttk.Frame(self.master)
        input_frame.pack(padx=10, pady=5, fill='x')

        # Mnemonic display
        ttk.Label(input_frame, text="Mnemonic:").grid(row=0, column=0, sticky='w')
        self.mnemonic_display = ttk.Entry(input_frame, state='readonly')
        self.mnemonic_display.grid(row=0, column=1, columnspan=3, sticky='ew', padx=5)

        # Passphrase input
        ttk.Label(input_frame, text="Passphrase:").grid(row=1, column=0, sticky='w')
        self.passphrase_entry = ttk.Entry(input_frame, show="*")
        self.passphrase_entry.grid(row=1, column=1, sticky='ew', padx=5)

        self.show_pass = tk.IntVar()
        ttk.Checkbutton(input_frame, text="Show Passphrase", variable=self.show_pass, command=self.toggle_passphrase).grid(row=1, column=2, padx=5)
        
        self.generate_mnemonic_button = ttk.Button(input_frame, text="Generate Mnemonic", command=self.generate_new_mnemonic)
        self.generate_mnemonic_button.grid(row=2, column=0, padx=5, pady=5)

        self.generate_wallet_button = ttk.Button(input_frame, text="Generate Wallet", command=self.generate_wallet)
        self.generate_wallet_button.grid(row=2, column=3, padx=5, pady=5)

        input_frame.grid_columnconfigure(1, weight=1)

    def setup_output_frame(self):
        """Setup the output frame for displaying generated wallet addresses."""
        output_frame = ttk.Frame(self.master)
        output_frame.pack(padx=10, pady=5, fill='both', expand=True)

        self.wallet_details = ttk.Treeview(output_frame, columns=('Index', 'Private Key', 'Public Key', 'Address'), show='headings')
        self.wallet_details.pack(fill='both', expand=True, pady=5)
        self.wallet_details.column('Index', width=50, minwidth=50, stretch=tk.NO)
        self.wallet_details.heading('Index', text='#')
        self.wallet_details.heading('Private Key', text='Private Key')
        self.wallet_details.heading('Public Key', text='Public Key')
        self.wallet_details.heading('Address', text='Address')

        scrollbar = ttk.Scrollbar(output_frame, orient="vertical", command=self.wallet_details.yview)
        scrollbar.pack(side='right', fill='y')
        self.wallet_details.configure(yscroll=scrollbar.set)

        self.wallet_details.bind("<Motion>", self.on_hover)
        self.wallet_details.bind("<Leave>", self.hide_qr_popup)
        
        # Bind both Button-3 and Control-Button-1 for macOS compatibility
        self.wallet_details.bind("<Button-2>", self.show_context_menu)
        self.wallet_details.bind("<Button-3>", self.show_context_menu)

    def setup_import_mode(self):
        """Setup the import mode for importing a wallet using a mnemonic."""
        import_frame = ttk.Labelframe(self.master, text="Import Wallet", padding=(10, 10))
        import_frame.pack(padx=10, pady=10, fill='x')

        ttk.Label(import_frame, text="Mnemonic:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.import_mnemonic_entry = ttk.Entry(import_frame, width=60)
        self.import_mnemonic_entry.grid(row=0, column=1, sticky='ew', padx=5, pady=5)

        ttk.Label(import_frame, text="Passphrase:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.import_passphrase_entry = ttk.Entry(import_frame, show="*")
        self.import_passphrase_entry.grid(row=1, column=1, sticky='ew', padx=5, pady=5)

        self.import_wallet_button = ttk.Button(import_frame, text="Import Wallet", command=self.import_wallet)
        self.import_wallet_button.grid(row=2, column=1, sticky='e', padx=5, pady=5)

    def setup_context_menu(self):
        """Setup the context menu for copying wallet details."""
        self.context_menu = tk.Menu(self.master, tearoff=0)
        self.context_menu.add_command(label="Copy", command=self.copy_to_clipboard)

    def show_context_menu(self, event):
        """Show the context menu on right-click or control-click for macOS."""
        try:
            self.wallet_details.selection_set(self.wallet_details.identify_row(event.y))  # Select the row under the cursor.
            region = self.wallet_details.identify("region", event.x, event.y)
            if region == "cell":
                row_id = self.wallet_details.identify_row(event.y)
                col = self.wallet_details.identify_column(event.x)
                if col in ["#2", "#3", "#4"]:  # Allow copying for private, public key, and address columns
                    self.selected_item = self.wallet_details.item(row_id)['values'][int(col[1]) - 1]
                    self.context_menu.tk_popup(event.x_root, event.y_root)
                else:
                    self.context_menu.entryconfig("Copy", state="disabled")
            else:
                self.context_menu.entryconfig("Copy", state="disabled")
        finally:
            # Make sure the menu is torn down properly on macOS
            self.context_menu.grab_release()

    def copy_to_clipboard(self):
        """Copy the selected wallet detail to the clipboard."""
        self.master.clipboard_clear()
        self.master.clipboard_append(self.selected_item)
        self.master.update()  # Now it stays on the clipboard after the window is closed

    def on_hover(self, event):
        region = self.wallet_details.identify("region", event.x, event.y)
        if region == "cell":
            row_id = self.wallet_details.identify_row(event.y)
            col = self.wallet_details.identify_column(event.x)
            if col in ["#2", "#3", "#4"]:  # Check if hovering over private, public key, or address columns
                data = self.wallet_details.item(row_id)['values'][int(col[1]) - 1]
                self.show_qr_popup(data, event.x_root, event.y_root)

    def show_qr_popup(self, data, x, y):
        if self.qr_popup:
            self.qr_popup.destroy()
        self.qr_popup = tk.Toplevel()
        self.qr_popup.wm_overrideredirect(True)
        self.qr_popup.geometry(f"+{x}+{y}")
        qr_image = ImageTk.PhotoImage(image=Image.open(io.BytesIO(generate_qr_code(data))))
        label = tk.Label(self.qr_popup, image=qr_image)
        label.pack()
        label.image = qr_image  # Keep a reference.

    def hide_qr_popup(self, event=None):
        if self.qr_popup:
            self.qr_popup.destroy()
            self.qr_popup = None
            
    def toggle_passphrase(self):
        """Toggle the visibility of the passphrase entry."""
        show = "" if self.show_pass.get() else "*"
        self.passphrase_entry.config(show=show)

    def generate_new_mnemonic(self):
        """Generate a new mnemonic and display it in the mnemonic display."""
        self.mnemonic = generate_mnemonic()
        self.mnemonic_display.config(state='normal')
        self.mnemonic_display.delete(0, tk.END)
        self.mnemonic_display.insert(0, self.mnemonic)
        self.mnemonic_display.config(state='readonly')

    def generate_wallet(self):
        """Generate a wallet using the current mnemonic and passphrase."""
        if not self.mnemonic:
            messagebox.showwarning("Warning", "Please generate or import a mnemonic first.")
            return

        passphrase = self.passphrase_entry.get()
        root_key = create_root_key(self.mnemonic, passphrase)
        
        # Clear existing entries in the wallet details treeview
        for item in self.wallet_details.get_children():
            self.wallet_details.delete(item)
        
        # Generate and display addresses
        for i in range(10):
            priv_key, pub_key, address = derive_address(root_key, account=0, change=0, address_index=i)
            self.wallet_details.insert('', 'end', values=(i + 1, priv_key, pub_key, address))

    def import_wallet(self):
        """Import a wallet using a provided mnemonic and passphrase."""
        mnemonic = self.import_mnemonic_entry.get()
        passphrase = self.import_passphrase_entry.get()

        if not Mnemonic("english").check(mnemonic):
            messagebox.showerror("Error", "Invalid mnemonic. Please check and try again.")
            return

        self.mnemonic = mnemonic
        self.passphrase_entry.delete(0, tk.END)
        self.passphrase_entry.insert(0, passphrase)
        self.generate_wallet()

def main():
    """Main function to run the Offline Wallet Application."""
    root = tk.Tk()
    root.geometry("1000x500")
    app = OfflineWalletApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
