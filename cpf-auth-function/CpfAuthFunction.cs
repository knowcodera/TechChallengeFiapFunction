using System;
using System.IO;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Data.SqlClient;
using System.Threading.Tasks;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

public static class CpfAuthFunction
{
    [FunctionName("CpfAuthFunction")]
    public static async Task<IActionResult> Run(
        [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)] HttpRequest req,
        ILogger log)
    {
        log.LogInformation("Iniciando o processamento da requisição de autenticação.");

        string requestBody;
        try
        {
            requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            log.LogInformation("Corpo da requisição lido com sucesso.");
        }
        catch (Exception ex)
        {
            log.LogError($"Erro ao ler o corpo da requisição: {ex.Message}");
            return new ObjectResult(new { error = "Erro ao ler o corpo da requisição.", details = ex.Message })
            {
                StatusCode = StatusCodes.Status500InternalServerError
            };
        }

        AuthenticationRequest data;
        try
        {
            data = JsonConvert.DeserializeObject<AuthenticationRequest>(requestBody);
            log.LogInformation("Dados da requisição desserializados com sucesso.");
        }
        catch (Exception ex)
        {
            log.LogError($"Erro ao desserializar os dados da requisição: {ex.Message}");
            return new BadRequestObjectResult(new { error = "Erro ao processar os dados da requisição.", details = ex.Message });
        }

        string cpf = data?.Cpf;
        string name = data?.Name;
        string email = data?.Email;

        if (string.IsNullOrEmpty(cpf))
        {
            log.LogWarning("CPF não foi fornecido.");
            return new BadRequestObjectResult(new { error = "CPF é obrigatório." });
        }

        if (cpf == "anonymous")
        {
            log.LogInformation("Usuário anônimo identificado.");
            return new OkObjectResult(new { Message = "Usuário anônimo" });
        }

        if (!IsValidCpf(cpf))
        {
            log.LogWarning($"CPF inválido fornecido: {cpf}");
            return new BadRequestObjectResult(new { error = "CPF inválido." });
        }

        string connectionString = Environment.GetEnvironmentVariable("SQLCONNSTR_SqlConnectionString");

        if (string.IsNullOrEmpty(connectionString))
        {
            log.LogError("A string de conexão com o banco de dados está vazia ou não foi definida.");
            return new ObjectResult(new { error = "A string de conexão com o banco de dados está vazia." })
            {
                StatusCode = StatusCodes.Status500InternalServerError
            };
        }
        else
        {
            log.LogInformation($"String de conexão obtida: {connectionString}");
        }


        try
        {
            log.LogInformation("Tentando conectar ao banco de dados...");
            using (SqlConnection conn = new SqlConnection(connectionString))
            {
                var token = string.Empty;

                await conn.OpenAsync();
                log.LogInformation("Conexão com o banco de dados estabelecida com sucesso.");

                string query = "SELECT * FROM Client WHERE Cpf = @Cpf";

                using (SqlCommand cmd = new SqlCommand(query, conn))
                {
                    cmd.Parameters.AddWithValue("@Cpf", cpf);

                    using (SqlDataReader reader = await cmd.ExecuteReaderAsync())
                    {
                        if (reader.HasRows)
                        {
                            await reader.ReadAsync();
                            log.LogInformation($"Cliente com CPF {cpf} encontrado no banco de dados.");

                            token = GenerateJwtToken(cpf, email);
                            return new OkObjectResult(new { Token = token });
                        }
                    }
                }

                if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(email))
                {
                    log.LogWarning("Nome ou email ausentes para o cadastro de um novo usuário.");
                    return new BadRequestObjectResult(new { error = "Nome e Email são obrigatórios para novos usuários." });
                }

                string insertQuery = "INSERT INTO Client (Name, Email, Cpf) VALUES (@Name, @Email, @Cpf)";
                using (SqlCommand insertCmd = new SqlCommand(insertQuery, conn))
                {
                    insertCmd.Parameters.AddWithValue("@Name", name);
                    insertCmd.Parameters.AddWithValue("@Email", email);
                    insertCmd.Parameters.AddWithValue("@Cpf", cpf);
                    await insertCmd.ExecuteNonQueryAsync();
                    log.LogInformation($"Novo cliente com CPF {cpf} cadastrado com sucesso.");
                }

                token = GenerateJwtToken(cpf, email);
                return new OkObjectResult(new { Token = token });
            }
        }
        catch (SqlException ex)
        {
            log.LogError($"Erro ao tentar conectar ao banco de dados: {ex.Message}");
            return new ObjectResult(new { error = "Erro ao tentar conectar ao banco de dados.", details = ex.Message })
            {
                StatusCode = StatusCodes.Status500InternalServerError
            };
        }
        catch (Exception ex)
        {
            log.LogError($"Erro inesperado: {ex.Message}");
            return new ObjectResult(new { error = "Erro inesperado.", details = ex.Message })
            {
                StatusCode = StatusCodes.Status500InternalServerError
            };
        }
    }

    private static string GenerateJwtToken(string cpf, string email)

    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("JwtSecretKey")));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, cpf),
            new Claim(JwtRegisteredClaimNames.Email, email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var token = new JwtSecurityToken(
            claims: claims,
            expires: DateTime.Now.AddHours(1),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public class AuthenticationRequest
    {
        public string Cpf { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
    }

    private static bool IsValidCpf(string cpf)
    {
        cpf = new string(cpf.Where(char.IsDigit).ToArray());

        if (cpf.Length != 11)
            return false;

        if (cpf.Distinct().Count() == 1)
            return false;

        int[] multiplicador1 = { 10, 9, 8, 7, 6, 5, 4, 3, 2 };
        int soma = 0;

        for (int i = 0; i < 9; i++)
            soma += int.Parse(cpf[i].ToString()) * multiplicador1[i];

        int resto = soma % 11;
        int digito1 = resto < 2 ? 0 : 11 - resto;

        int[] multiplicador2 = { 11, 10, 9, 8, 7, 6, 5, 4, 3, 2 };
        soma = 0;

        for (int i = 0; i < 10; i++)
            soma += int.Parse(cpf[i].ToString()) * multiplicador2[i];

        resto = soma % 11;
        int digito2 = resto < 2 ? 0 : 11 - resto;

        return cpf[9].ToString() == digito1.ToString() && cpf[10].ToString() == digito2.ToString();
    }
}
