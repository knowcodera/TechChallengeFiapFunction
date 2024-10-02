# TechChallengeFiap - API Gateway e Function

Este repositório contém uma função Azure Functions para autenticação de usuários baseada em CPF, que utiliza um banco de dados SQL e gera tokens JWT (JSON Web Token) para autenticação segura. A função também realiza a integração com o Azure API Gateway para expor a API.

## Descrição

A função **CpfAuthFunction** permite que os usuários se autentiquem utilizando o CPF. Dependendo das informações fornecidas na requisição, a função pode:

- Verificar se o CPF já está cadastrado no banco de dados.
- Retornar um token JWT para o usuário autenticado.
- Cadastrar um novo usuário no banco de dados caso o CPF não esteja registrado, exigindo os campos `Nome` e `Email` para novos cadastros.
- Validar o formato do CPF e impedir a criação de entradas com CPFs inválidos.

## Funcionalidades

- **Validação de CPF**: Verifica se o CPF fornecido está no formato correto antes de prosseguir com a autenticação ou cadastro.
- **Autenticação JWT**: Gera um token JWT para o usuário autenticado, que pode ser usado para acessar outros serviços.
- **Banco de Dados**: Verifica a existência do CPF no banco de dados SQL. Se o CPF já existir, autentica o usuário. Se não existir, cadastra um novo usuário com os dados fornecidos.
- **Log de Erros**: Implementa logs detalhados para monitoramento de erros e sucessos no processamento das requisições.

## Tecnologias Utilizadas

- **Azure Functions**: Plataforma de computação sem servidor que permite a execução de funções em resposta a eventos HTTP.
- **Azure API Gateway**: Serviço que expõe a função como uma API REST para o mundo externo.
- **SQL Server**: Banco de dados relacional utilizado para armazenar informações dos usuários.
- **JWT (JSON Web Token)**: Para autenticação segura de usuários.
- **C#**: Linguagem de programação utilizada para implementar a função.
- **Newtonsoft.Json**: Biblioteca para serialização e desserialização de objetos JSON.
- **Microsoft IdentityModel Tokens**: Biblioteca usada para gerar e validar tokens JWT.


## Variáveis de Ambiente

- `SQLCONNSTR_SqlConnectionString`: String de conexão para o banco de dados SQL.
- `JwtSecretKey`: Chave secreta utilizada para assinar os tokens JWT.

Essas variáveis de ambiente devem ser configuradas no Azure para garantir o funcionamento correto da função.

## Exemplo de Requisição POST

```json
{
  "cpf": "12345678901",
  "name": "Nome do Usuário",
  "email": "email@example.com"
}
```

Seguindo com anonimo 
```json
{
  "cpf": "anonymous",
  "name": "Nome do Usuário",
  "email": "email@example.com"
}
```
