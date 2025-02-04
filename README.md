# secure-vault


Secure Vault is a Python-based file management system designed for securely storing, encrypting, and managing files. It uses advanced encryption techniques to protect your data and provides an easy-to-use graphical interface for interaction.

## Features

-> **Create Encrypted Vaults:** Users can create vaults with a password to securely store files.

-> **File Encryption:** Files are encrypted when added to the vault, ensuring their security.

-> **File Management:** Add, list, remove, and extract files from the vault through the graphical interface.

-> **Integrity Check:** Ensures that files are not tampered with inside the vault.

-> **Metadata Handling:** Securely stores file metadata, such as file offsets, sizes, and hashes.

-> **Padding for Security:** Vault files are padded to hide their true size, improving security.

-> **Graphical User Interface (GUI):** Built with Tkinter, the GUI provides a user-friendly experience.


## How to Run

Follow these steps to set up and run the Secure Vault project:

### 1. Clone the Repository
```bash
git clone https://github.com/selimyilbas/secure-vault.git
cd secure-vault
```


### 2. Set Up a Virtual Environment

Create a virtual environment to manage dependencies:


python3 -m venv venv


Activate the virtual environment:

On macOS/Linux:

```bash
source venv/bin/activate
```

On Windows:

```bash
venv\Scripts\activate
```

### 3. Install Dependencies
Install the required Python libraries:

```bash
pip install pillow
pip install cryptography
```

### 4. Run the Application
   
Start the Secure Vault GUI:

```bash
python3 gui.py
```

## Usage

-> **Create a Vault:** Enter a vault path and password, then click "Create Vault."

-> **Open a Vault:** Use the same vault path (use .vault after your username to relogin after the vault has created) and password to access an existing vault.

-> **Add Files:** Add files to the vault for encryption.

-> **Extract Files:** Extract encrypted files back to their original state.

-> **Lock Vault:** Securely lock the vault when you're done.

-> **Exit the Application**

-> Simply close the GUI window to exit.





