import os
import tkinter as tk
from tkinter import filedialog, messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64


class FileCryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("FileCryptor")
        self.root.geometry("500x480")  # Ajustado para novo botão
        self.root.resizable(False, False)

        # Inicializa ttkbootstrap com tema padrão
        self.style = ttk.Style(theme="flatly")
        self.current_theme = "flatly"

        # Layout
        self.create_widgets()

    def create_widgets(self):
        # Título
        ttk.Label(self.root, text="FileCryptor", font=("Arial", 16, "bold"), bootstyle="primary").pack(pady=10)

        # Frame para seleção de arquivo
        self.file_frame = ttk.Frame(self.root)
        self.file_frame.pack(pady=10, fill="x", padx=20)

        ttk.Label(self.file_frame, text="Arquivo:", font=("Arial", 12), bootstyle="default").pack(side="left")
        self.file_entry = ttk.Entry(self.file_frame, width=40, font=("Arial", 10))
        self.file_entry.pack(side="left", padx=5)
        ttk.Button(self.file_frame, text="Selecionar", bootstyle="success", command=self.select_file).pack(side="left")

        # Frame para seleção de pasta
        self.folder_frame = ttk.Frame(self.root)
        self.folder_frame.pack(pady=10, fill="x", padx=20)

        ttk.Label(self.folder_frame, text="Pasta:", font=("Arial", 12), bootstyle="default").pack(side="left")
        self.folder_entry = ttk.Entry(self.folder_frame, width=40, font=("Arial", 10))
        self.folder_entry.pack(side="left", padx=5)
        ttk.Button(self.folder_frame, text="Selecionar", bootstyle="success", command=self.select_folder).pack(
            side="left")

        # Frame para senha
        self.password_frame = ttk.Frame(self.root)
        self.password_frame.pack(pady=10, fill="x", padx=20)

        ttk.Label(self.password_frame, text="Senha:", font=("Arial", 12), bootstyle="default").pack(side="left")
        self.password_entry = ttk.Entry(self.password_frame, width=40, font=("Arial", 10), show="*")
        self.password_entry.pack(side="left", padx=5)
        self.show_password_var = tk.BooleanVar()
        ttk.Checkbutton(self.password_frame, text="Mostrar", variable=self.show_password_var, bootstyle="round-toggle",
                        command=self.toggle_password).pack(side="left")

        # Botões de ação
        self.action_frame = ttk.Frame(self.root)
        self.action_frame.pack(pady=20)

        ttk.Button(self.action_frame, text="Criptografar", bootstyle="success", command=self.encrypt, width=15).pack(
            side="left", padx=10)
        ttk.Button(self.action_frame, text="Descriptografar", bootstyle="success", command=self.decrypt, width=15).pack(
            side="left", padx=10)

        # Botão de alternância de tema
        self.theme_frame = ttk.Frame(self.root)
        self.theme_frame.pack(pady=10)
        ttk.Button(self.theme_frame, text="Alternar Tema", bootstyle="info", command=self.toggle_theme).pack()

    def toggle_theme(self):
        # Alterna entre temas flatly e darkly
        self.current_theme = "darkly" if self.current_theme == "flatly" else "flatly"
        self.style.theme_use(self.current_theme)
        # Atualiza o estilo do título para manter consistência
        self.root.nametowidget(".!label").configure(bootstyle="primary")

    def toggle_password(self):
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, file_path)
            self.folder_entry.delete(0, tk.END)  # Limpa o campo de pasta

    def select_folder(self):
        folder_path = filedialog.askdirectory()
        if folder_path:
            self.folder_entry.delete(0, tk.END)
            self.folder_entry.insert(0, folder_path)
            self.file_entry.delete(0, tk.END)  # Limpa o campo de arquivo

    def generate_key(self, password):
        password = password.encode()
        salt = b'salt_fixed_for_demo'  # Em produção, use os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key

    def encrypt_file(self, file_path, password, fernet):
        try:
            with open(file_path, 'rb') as file:
                file_data = file.read()

            encrypted_data = fernet.encrypt(file_data)

            encrypted_file_path = file_path + '.encrypted'
            with open(encrypted_file_path, 'wb') as file:
                file.write(encrypted_data)

            return f"Sucesso: {encrypted_file_path}"
        except Exception as e:
            return f"Erro em {file_path}: {str(e)}"

    def decrypt_file(self, file_path, password, fernet):
        try:
            with open(file_path, 'rb') as file:
                encrypted_data = file.read()

            decrypted_data = fernet.decrypt(encrypted_data)
            decrypted_file_path = file_path.replace('.encrypted', '.decrypted')

            with open(decrypted_file_path, 'wb') as file:
                file.write(decrypted_data)

            return f"Sucesso: {decrypted_file_path}"
        except Exception as e:
            return f"Erro em {file_path}: {str(e)}"

    def encrypt(self):
        file_path = self.file_entry.get()
        folder_path = self.folder_entry.get()
        password = self.password_entry.get()

        if not (file_path or folder_path):
            messagebox.showerror("Erro", "Selecione um arquivo ou pasta!", bootstyle="danger")
            return
        if not password:
            messagebox.showerror("Erro", "Digite uma senha!", bootstyle="danger")
            return

        try:
            key = self.generate_key(password)
            fernet = Fernet(key)
            results = []

            if file_path and os.path.exists(file_path):
                results.append(self.encrypt_file(file_path, password, fernet))

            if folder_path and os.path.exists(folder_path):
                for filename in os.listdir(folder_path):
                    file_path = os.path.join(folder_path, filename)
                    if os.path.isfile(file_path):
                        results.append(self.encrypt_file(file_path, password, fernet))

            messagebox.showinfo("Resultado", "\n".join(results) + "\n\nGuarde sua senha com segurança!",
                                bootstyle="success")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao criptografar: {str(e)}", bootstyle="danger")

    def decrypt(self):
        file_path = self.file_entry.get()
        folder_path = self.folder_entry.get()
        password = self.password_entry.get()

        if not (file_path or folder_path):
            messagebox.showerror("Erro", "Selecione um arquivo ou pasta!", bootstyle="danger")
            return
        if not password:
            messagebox.showerror("Erro", "Digite uma senha!", bootstyle="danger")
            return

        try:
            key = self.generate_key(password)
            fernet = Fernet(key)
            results = []

            if file_path and os.path.exists(file_path):
                results.append(self.decrypt_file(file_path, password, fernet))

            if folder_path and os.path.exists(folder_path):
                for filename in os.listdir(folder_path):
                    file_path = os.path.join(folder_path, filename)
                    if os.path.isfile(file_path) and file_path.endswith('.encrypted'):
                        results.append(self.decrypt_file(file_path, password, fernet))

            messagebox.showinfo("Resultado", "\n".join(results), bootstyle="success")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao descriptografar: {str(e)}", bootstyle="danger")


if __name__ == "__main__":
    root = ttk.Window()
    app = FileCryptorApp(root)
    root.mainloop()