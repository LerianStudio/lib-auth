# Authorization Middleware for Lerian Services

Este repositório contém um middleware de autorização para o framework Fiber em Go, que permite verificar se um usuário está autorizado a realizar uma ação específica em um recurso. O middleware envia uma solicitação POST para um serviço de autorização, passando os detalhes do usuário, recurso e ação desejada.

## 📦 Instalação

```bash
go get -u github.com/gofiber/fiber/v2
```

## 🚀 Como Usar

### 1. Crie uma instância do `AuthClient`:

```go
import "github.com/suapasta/middleware"

authClient := &middleware.AuthClient{
    AuthAddress: "http://localhost:3000",
}
```

### 2. Use o middleware na sua aplicação Fiber:

```go
app := fiber.New()

app.Use(authClient.Authorize("user123", "resource_name", "read"))

app.Get("/resource", func(c *fiber.Ctx) error {
    return c.SendString("Você tem permissão para acessar este recurso!")
})

app.Listen(":8080")
```

## 🛠️ Funcionamento

A função `Authorize`:

- Recebe o `sub` (usuário), `resource` (recurso) e `action` (ação desejada).
- Envia uma solicitação POST ao serviço de autorização.
- Verifica se a resposta indica que o usuário está autorizado.
- Permite o fluxo normal da aplicação ou retorna um erro 403 (Forbidden).

## 📥 Exemplo de Requisição

```http
POST /v1/authorize
Content-Type: application/json
Authorization: Bearer seu_token_aqui

{
    "sub": "lerian/user123_role",
    "resource": "resource_name",
    "action": "read"
}
```

## 📡 Serviço de Autorização Esperado

O serviço de autorização deve retornar uma resposta JSON no seguinte formato:

```json
{
    "authorized": true,
    "timestamp": "2025-03-03T12:00:00Z"
}
```

## 🚧 Tratamento de Erros

O middleware captura e exibe logs para os seguintes tipos de erro:

- Falha ao criar a requisição
- Falha ao enviar a requisição
- Falha ao ler o corpo da resposta
- Falha ao desserializar o JSON de resposta

## 📄 Licença

Este projeto está licenciado sob a licença MIT. Sinta-se à vontade para usá-lo e modificá-lo conforme necessário.

## 🧑‍💻 Contribuindo

Contribuições são bem-vindas! Abra uma issue ou um pull request para sugestões e melhorias.

## 📧 Contato

Para dúvidas ou suporte, entre em contato pelo e-mail: contato\@lerian.studio.

