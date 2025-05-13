
FileCryptor

Um projeto em Python para criptografar e descriptografar arquivos usando a biblioteca cryptography. Inclui uma interface gráfica moderna com ttkbootstrap, ideal para proteger arquivos sensíveis.

Funcionalidades:

Criptografia de arquivos: Proteja arquivos individuais ou em lote com uma senha usando o algoritmo AES.
Descriptografia de arquivos: Recupere arquivos com a senha correta.
Criptografia em lote: Criptografe/descriptografe todos os arquivos de uma pasta.
Interface gráfica: Interface moderna com temas claro/escuro, seleção de arquivos/pastas e feedback visual.
Interface de linha de comando: Disponível em filecryptor.py para usuários avançados.

Uso
Interface Gráfica 

Abra o aplicativo executando python app.py.
Escolha uma opção:
Selecionar arquivo: Clique em "Selecionar" no campo "Arquivo" para escolher um arquivo.
Selecionar pasta: Clique em "Selecionar" no campo "Pasta" para processar todos os arquivos de uma pasta.


Digite uma senha no campo correspondente.
Clique em "Criptografar" ou "Descriptografar":
Criptografar: Gera arquivos com extensão .encrypted.
Descriptografar: Gera arquivos com extensão .decrypted.

Use o botão "Alternar Tema" para mudar entre os modos claro e escuro.
Mensagens de sucesso ou erro serão exibidas.

Execute python filecryptor.py.
Escolha a opção no menu:
1. Criptografar arquivo: Informe o caminho do arquivo e uma senha.
2. Descriptografar arquivo: Informe o caminho do arquivo criptografado e a senha.
3. Sair: Encerra o programa.


Aviso

Guarde sua senha com segurança! Sem ela, não é possível recuperar os arquivos criptografados.

Licença
Distribuído sob a licença MIT.
Contato
Desenvolvido por Fernando Cardoso 
