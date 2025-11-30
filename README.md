# DockShield - Sistema de Análise de Vulnerabilidades em Containers

Disciplina: Ferramentas de Desenvolvimento Web (FDW)

Semestre: 2025/2

Instituição: Fatec São Caetano do Sul

#### Link do video sobre o projeto: https://youtu.be/u7s5HNsFLg0

## 1. Visão Geral do Projeto

O DockShield é uma solução de software desenvolvida sob a arquitetura de microsserviços, projetada para gerenciar e visualizar relatórios de segurança de imagens de containers. O sistema permite que administradores de sistemas autentiquem-se de forma segura e acessem dashboards detalhados sobre vulnerabilidades (CVEs) detectadas em sua infraestrutura Docker.

Este projeto constitui o Produto Mínimo Viável (MVP) exigido para a avaliação N2, integrando desenvolvimento full-stack (Node.js e Python) com orquestração de infraestrutura (Docker).

## 2. Arquitetura e Tecnologias

O sistema é composto por três serviços isolados que se comunicam através de uma rede interna containerizada:

### 2.1. Serviço de Autenticação (Frontend)

- Tecnologia: Node.js com Express Framework.

- Responsabilidade: Gerenciamento de identidade, cadastro, login e emissão de tokens de sessão (JWT).

- Segurança: Implementação de hashing de senhas e cookies HttpOnly.

### 2.2. Serviço de Aplicação (Backend)

- Tecnologia: Python com Flask, servido via Apache HTTP Server (mod_wsgi).

- Responsabilidade: Regras de negócio, conexão com base de dados de vulnerabilidades e renderização de relatórios.

- Segurança: Middleware de validação de tokens JWT para proteção de rotas.

### 2.3. Persistência de Dados

- Tecnologia: MongoDB (v4.4).

- Responsabilidade: Armazenamento não-relacional de credenciais de usuários e documentos de análise de segurança.

## 3. Entrega via DockerHub (Imagens Oficiais)

Em conformidade com o requisito 2.7 da especificação do projeto, as imagens dos serviços foram compiladas e publicadas no registro público DockerHub. Isso permite a execução do ambiente sem a necessidade de compilação local do código-fonte.

Os repositórios oficiais são:

### Frontend (Node.js):
```bash
docker.io/avaliacaon2/fatec-scs-imagem-dockshield-frontend
```

Backend (Flask):
```bash
docker.io/avaliacaon2/fatec-scs-imagem-dockshield-backend
```

Database (MongoDB):
```bash
docker.io/avaliacaon2/fatec-scs-imagem-dockshield-db
```

## 4. Instruções de Instalação e Execução

Para implantar o sistema em um ambiente limpo (servidor Linux ou máquina local), siga os procedimentos abaixo.

### 4.1. Pré-requisitos

- Docker Engine instalado.

- Docker Compose instalado.

- Conexão com a internet (para pull das imagens).

### 4.2. Obtenção dos Arquivos de Orquestração

Clone este repositório ou realize o download dos arquivos docker-compose.yml e web_config.ini para um diretório local.
```bash
git clone https://github.com/G-Bitencourt/fatec-scs-fdw-2025-2-DockShield
```
```bash
cd fatec-scs-fdw-2025-2-DockShield/P2
```

### 4.3. Configuração de Rede (Mandatório)

O sistema utiliza redirecionamentos HTTP entre os serviços. Para garantir o funcionamento correto, é necessário configurar o endereço IP da máquina hospedeira.

#### Passo A: Identifique seu IP
Execute o comando `ip addr` (Linux) ou `ipconfig` (Windows) e anote o endereço IPv4 da interface de rede principal (exemplo: 192.168.0.102).


#### Passo B: Configure o Orquestrador
Abra o arquivo docker-compose.yml e localize a variável de ambiente FLASK_EXTERNAL_URL no serviço frontend. Substitua localhost pelo seu IP.

```bash
FLASK_EXTERNAL_URL=http://SEU_IP_AQUI:5000/
```


#### Passo C: Configure o Servidor Web
Abra o arquivo web_config.ini e localize a chave url_node. Substitua localhost pelo seu IP.
```bash
[LOGIN]
url_node = http://SEU_IP_AQUI:3000/login.html
```


### 4.4. Inicialização do Ambiente

Execute o comando abaixo para baixar as imagens do DockerHub e iniciar os containers:
```bash
sudo docker-compose up
```

Após a inicialização, o sistema estará acessível através do navegador no endereço:
```bash
http://SEU_IP_AQUI:3000/login.html
```
## 5. Documentação Complementar

A documentação técnica completa do projeto encontra-se disponível no diretório /Documentos deste repositório, contendo:

- Proposta Técnica: Escopo e objetivos iniciais.

- Relatório Técnico: Detalhamento da implementação e tecnologias.

- Plano de Testes: Roteiro para validação funcional.
