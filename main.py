import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class Criptografia:
    def __init__(self):
        self.chave = None

    def gerar_chave(self):
        self.chave = get_random_bytes(32)  # 32 bytes para AES-256
        with open('chave_privada.bin', 'wb') as arquivo_chave:
            arquivo_chave.write(self.chave)

    def carregar_chave(self, arquivo_chave):
        with open(arquivo_chave, 'rb') as arquivo:
            self.chave = arquivo.read()

    def criptografar_arquivo(self, arquivo_entrada):
        if self.chave is None:
            self.gerar_chave()

        with open(arquivo_entrada, 'rb') as arquivo:
            dados = arquivo.read()

        cipher = AES.new(self.chave, AES.MODE_EAX)
        nonce = cipher.nonce
        dados_criptografados, tag = cipher.encrypt_and_digest(dados)

        arquivo_criptografado_nome = f"{arquivo_entrada}.criptografado"
        with open(arquivo_criptografado_nome, 'wb') as arquivo_criptografado:
            arquivo_criptografado.write(nonce)
            arquivo_criptografado.write(tag)
            arquivo_criptografado.write(dados_criptografados)
        return arquivo_criptografado_nome

    def descriptografar_arquivo(self, arquivo_criptografado):
        if self.chave is None:
            raise ValueError("Chave de criptografia não carregada. Carregue a chave privada primeiro.")

        with open(arquivo_criptografado, 'rb') as arquivo:
            nonce = arquivo.read(16)
            tag = arquivo.read(16)
            dados_criptografados = arquivo.read()

        cipher = AES.new(self.chave, AES.MODE_EAX, nonce=nonce)
        dados_descriptografados = cipher.decrypt_and_verify(dados_criptografados, tag)

        arquivo_descriptografado_nome = arquivo_criptografado.replace('.criptografado', '.descriptografado')
        with open(arquivo_descriptografado_nome, 'wb') as arquivo_descriptografado:
            arquivo_descriptografado.write(dados_descriptografados)
        return arquivo_descriptografado_nome

class InterfaceGrafica:
    def __init__(self, root):
        self.root = root
        self.root.title("Armazenar Chave")
        self.root.geometry("400x300")
        fonte_personalizada = ("Arial", 14)

        self.escolha_label = tk.Label(root, text="Escolha o número de palavras:", font=fonte_personalizada)
        self.escolha_label.pack()

        self.botao_12 = tk.Button(root, text="12 Palavras", command=lambda: self.inserir_palavras(12))
        self.botao_24 = tk.Button(root, text="24 Palavras", command=lambda: self.inserir_palavras(24))
        self.botao_12.pack()
        self.botao_24.pack()

        self.criptografia = Criptografia()

        self.carregar_chave_button = tk.Button(root, text="Carregar Chave Privada", command=self.carregar_chave)
        self.carregar_chave_button.pack()

        self.descriptografar_button = tk.Button(root, text="Descriptografar Arquivo", command=self.descriptografar_arquivo)
        self.descriptografar_button.pack()

    def inserir_palavras(self, quantidade):
        self.root.withdraw()
        janela_palavras = tk.Toplevel(self.root)
        janela_palavras.title(f"Inserir {quantidade} Palavras")

        self.palavras = []
        self.contador = 1

        label = tk.Label(janela_palavras, text=f"Insira {quantidade} palavras:")
        label.pack()

        self.entry = tk.Entry(janela_palavras, width=30)
        self.entry.pack()

        self.botao_adicionar = tk.Button(janela_palavras, text="Adicionar Palavra", command=self.adicionar_palavra)
        self.botao_adicionar.pack()

        self.salvar_button = tk.Button(janela_palavras, text="Salvar em Arquivo", command=self.salvar_em_arquivo)
        self.salvar_button.pack()

        self.texto = tk.Text(janela_palavras, height=15, width=40)
        self.texto.pack()

        self.quantidade_palavras = quantidade

        self.botao_criptografar = tk.Button(janela_palavras, text="Criptografar Palavras", command=self.criptografar_palavras)
        self.botao_criptografar.pack()

    def adicionar_palavra(self):
        if len(self.palavras) < self.quantidade_palavras:
            palavra = self.entry.get()
            if palavra:
                self.palavras.append(palavra)
                self.texto.insert(tk.END, f"{self.contador}.{palavra}\n")
                self.contador += 1
                self.entry.delete(0, tk.END)
            if len(self.palavras) == self.quantidade_palavras:
                self.botao_adicionar.config(state=tk.DISABLED)
                self.salvar_button.config(state=tk.NORMAL)
                self.botao_criptografar.config(state=tk.NORMAL)
        else:
            self.botao_adicionar.config(state=tk.DISABLED)

    def salvar_em_arquivo(self):
        if len(self.palavras) == self.quantidade_palavras:
            with open("palavras.txt", "w") as arquivo:
                for palavra in self.palavras:
                    arquivo.write(f"{palavra}\n")
            messagebox.showinfo("Sucesso", "Palavras salvas em 'palavras.txt'")
        else:
            messagebox.showerror("Erro", f"Você precisa inserir {self.quantidade_palavras} palavras primeiro.")

    def criptografar_palavras(self):
        arquivo_entrada = 'palavras.txt'
        try:
            arquivo_criptografado = self.criptografia.criptografar_arquivo(arquivo_entrada)
            messagebox.showinfo("Sucesso", f"Arquivo criptografado com sucesso! Chave salva em 'chave_privada.bin'")
        except Exception as e:
            messagebox.showerror("Erro", f"Ocorreu um erro durante a criptografia: {e}")

    def carregar_chave(self):
        arquivo_chave = filedialog.askopenfilename(
            title="Selecione o arquivo da chave privada",
            filetypes=[("Chave Binária", "*.bin")]
        )
        if arquivo_chave:
            try:
                self.criptografia.carregar_chave(arquivo_chave)
                messagebox.showinfo("Sucesso", "Chave privada carregada com sucesso!")
            except Exception as e:
                messagebox.showerror("Erro", f"Ocorreu um erro ao carregar a chave: {e}")

    def descriptografar_arquivo(self):
        arquivo_criptografado = filedialog.askopenfilename(
            title="Selecione o arquivo criptografado",
            filetypes=[("Todos os Arquivos", "*.*")]
        )

        if arquivo_criptografado:
            try:
                self.criptografia.descriptografar_arquivo(arquivo_criptografado)
                messagebox.showinfo("Sucesso", f"Arquivo descriptografado com sucesso como '{arquivo_criptografado.replace('*.*', '.txt')}'")
            except Exception as e:
                messagebox.showerror("Erro", f"Ocorreu um erro durante a descriptografia: {e}")
        else:
            messagebox.showwarning("Aviso", "Nenhum arquivo selecionado para descriptografar.")

if __name__ == "__main__":
    root = tk.Tk()
    app = InterfaceGrafica(root)
    root.mainloop()
