# EMA Hardening Security
![WordPress Plugin Version](https://img.shields.io/badge/Version-1.3.1-blue.svg)
![WordPress Version](https://img.shields.io/badge/WordPress-5.0+-brightgreen.svg)
![License](https://img.shields.io/badge/License-GPLv2-orange.svg)

**Autor:** Eberton M. Alvares

Um plugin de segurança completo para WordPress, projetado para proteger, monitorar e reparar seu site contra as ameaças mais comuns. Desenvolvido com foco em performance, precisão e facilidade de uso.

---

## Tabela de Conteúdos

- [Visão Geral](#visão-geral)
- [Funcionalidades Principais](#funcionalidades-principais)
- [Instalação](#instalação)
- [Como Usar](#como-usar)
  - [Dashboard Principal](#dashboard-principal)
  - [Scanner de Segurança](#scanner-de-segurança)
  - [Log de Atividades](#log-de-atividades)
- [Estrutura dos Arquivos](#estrutura-dos-arquivos)
- [Como Contribuir](#como-contribuir)
- [Licença](#licença)

---

## Visão Geral

O **EMA Hardening Security** é uma suíte de segurança para WordPress que visa eliminar os vetores de ataque mais comuns e fornecer ferramentas de monitoramento e recuperação. Diferente de plugins pesados, ele foi construído para ser leve e eficiente, aplicando as melhores práticas de segurança sem comprometer a performance do site.

O plugin atua em múltiplas frentes:
- **Prevenção:** Bloqueia ataques em tempo real com um firewall e fortalece as defesas nativas do WordPress.
- **Detecção:** Identifica modificações não autorizadas, malware e atividades suspeitas através de um scanner completo e um log de auditoria.
- **Recuperação:** Permite a restauração de arquivos do core do WordPress com um único clique.

---

## Funcionalidades Principais

#### 🛡️ Firewall de Aplicação Web (WAF)
- Bloqueia em tempo real requisições maliciosas contendo padrões de **SQL Injection**, **Cross-Site Scripting (XSS)** e **Directory Traversal** antes que atinjam o WordPress.

#### 🔒 Proteção de Login
- Limita o número de tentativas de login falhas por endereço IP, prevenindo ataques de **força bruta**.
- IPs que excedem o limite são temporariamente bloqueados para mitigar ataques automatizados.

#### ⚙️ Hardening (Fortalecimento do Core)
- **Desabilita o editor de arquivos** do painel para prevenir modificações não autorizadas.
- **Oculta a versão do WordPress** para dificultar o trabalho de scanners de vulnerabilidades.
- **Bloqueia completamente o acesso ao XML-RPC**, um vetor comum de ataques de força bruta e DDoS.
- **Protege a API REST** contra a enumeração de usuários, impedindo que atacantes descubram nomes de usuário válidos.
- Adiciona **cabeçalhos de segurança HTTP** para proteger contra clickjacking, XSS e sniffing de conteúdo.

#### 🚫 Anti-Spam
- Implementa um campo **"honeypot" invisível** nos formulários de comentário para enganar e bloquear bots de spam.
- IPs identificados como spam são adicionados a uma lista de bloqueio.

#### 🕵️ Scanner de Segurança Completo
- Um scanner multi-etapas que verifica toda a sua instalação do WordPress de forma segura e sem sobrecarregar o servidor:
    - **Integridade do Core:** Compara os arquivos do `wp-admin` e `wp-includes` com os originais do WordPress.org.
        - **Reparo Automático:** Permite restaurar arquivos do core modificados e deletar arquivos desconhecidos com um único clique.
    - **Scan de Malware:** Verifica todos os arquivos do site (incluindo `wp-content`) em busca de assinaturas de malware e backdoors conhecidos.
    - **Scan de Banco de Dados:** Analisa seus posts e páginas em busca de conteúdo suspeito (scripts/iframes), verifica a integridade das URLs do site e lista os usuários administradores para revisão.

#### 📊 Log de Atividades
- Mantém um registro detalhado (trilha de auditoria) de todos os eventos importantes que ocorrem no site, como:
    - Logins bem-sucedidos e falhos.
    - Ativação e desativação de plugins.
    - Troca de temas.
    - Criação, atualização e exclusão de posts e usuários.

---

## Instalação

#### A partir do GitHub:
1.  Faça o download do repositório como um arquivo `.zip`.
2.  No painel do WordPress, vá para **Plugins > Adicionar Novo**.
3.  Clique em **Enviar plugin** e escolha o arquivo `.zip` que você baixou.
4.  Instale e ative o plugin.

#### Manualmente:
1.  Clone ou faça o download do repositório.
2.  Faça o upload da pasta `ema-hardening` para o seu diretório de plugins (`/wp-content/plugins/`).
3.  Acesse o menu "Plugins" no painel do WordPress.
4.  Ative o plugin "EMA Hardening Security".

Após a ativação, as funcionalidades de proteção serão ativadas automaticamente.

---

## Como Usar

Após a ativação, um novo menu chamado **"EMA Security"** aparecerá no seu painel.

### Dashboard Principal
-   **Local:** `EMA Security`
-   **Descrição:** Esta é a página principal. Ela mostra um resumo do status de todas as proteções ativas e um log dos últimos IPs bloqueados pelo firewall ou pelo sistema anti-spam.

### Scanner de Segurança
-   **Local:** `EMA Security > Scanner de Segurança`
-   **Como Usar:**
    1.  Navegue até a página para iniciar uma verificação completa.
    2.  Clique em **"Iniciar Verificação Completa"**.
    3.  Aguarde o processo terminar. O status será atualizado em tempo real, mostrando cada etapa da verificação.
    4.  Analise os resultados. Se arquivos do core forem sinalizados, você terá a opção de **"Restaurar"** (para arquivos modificados) ou **"Deletar"** (para arquivos desconhecidos).

### Log de Atividades
-   **Local:** `EMA Security > Log de Atividades`
-   **Descrição:** Esta página exibe a trilha de auditoria de tudo o que acontece no seu site. Use-a para monitorar a atividade de usuários e identificar ações suspeitas.

---

## Estrutura dos Arquivos
ema-hardening/
├── admin/
│ ├── ema-admin-page.php # Dashboard principal
│ ├── ema-logs-page.php # Página do Log de Atividades
│ ├── ema-scanner-page.php # Página do Scanner de Segurança
│ └── js/
│ └── scanner.js # Lógica JavaScript para o scanner
├── includes/
│ ├── ema-activity-logger.php # Lógica de registro de eventos
│ ├── ema-anti-spam.php # Funções de honeypot e bloqueio de spam
│ └── ema-hardening-functions.php # Funções de fortalecimento e segurança
├── ema-hardening.php # Arquivo principal do plugin
└── README.md # Este arquivo
code
Code
---

## Como Contribuir

Contribuições são bem-vindas! Se você deseja melhorar o plugin, por favor, siga os seguintes passos:

1.  **Faça um Fork** do repositório.
2.  **Crie uma nova Branch** para sua feature (`git checkout -b feature/minha-feature`).
3.  **Faça o Commit** das suas alterações (`git commit -m 'Adiciona minha-feature'`).
4.  **Faça o Push** para a Branch (`git push origin feature/minha-feature`).
5.  **Abra um Pull Request**.