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

public static class CpfAuthFunction
{
    [FunctionName("CpfAuthFunction")]
    public static async Task<IActionResult> Run(
        [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)] HttpRequest req,
        ILogger log)
    {
        log.LogInformation("Iniciando o processamento da requisi��o de autentica��o.");

        string requestBody;
        try
        {
            requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            log.LogInformation("Corpo da requisi��o lido com sucesso.");
        }
        catch (Exception ex)
        {
            log.LogError($"Erro ao ler o corpo da requisi��o: {ex.Message}");
            return new ObjectResult(new { error = "Erro ao ler o corpo da requisi��o.", details = ex.Message })
            {
                StatusCode = StatusCodes.Status500InternalServerError
            };
        }

        AuthenticationRequest data;
        try
        {
            data = JsonConvert.DeserializeObject<AuthenticationRequest>(requestBody);
            log.LogInformation("Dados da requisi��o desserializados com sucesso.");
        }
        catch (Exception ex)
        {
            log.LogError($"Erro ao desserializar os dados da requisi��o: {ex.Message}");
            return new BadRequestObjectResult(new { error = "Erro ao processar os dados da requisi��o.", details = ex.Message });
        }

        string cpf = data?.Cpf;
        string name = data?.Name;
        string email = data?.Email;

        if (string.IsNullOrEmpty(cpf))
        {
            log.LogWarning("CPF n�o foi fornecido.");
            return new BadRequestObjectResult(new { error = "CPF � obrigat�rio." });
        }

        if (cpf == "anonymous")
        {
            log.LogInformation("Usu�rio an�nimo identificado.");
            return new OkObjectResult(new { Message = "Usu�rio an�nimo" });
        }

        if (!IsValidCpf(cpf))
        {
            log.LogWarning($"CPF inv�lido fornecido: {cpf}");
            return new BadRequestObjectResult(new { error = "CPF inv�lido." });
        }

        string connectionString = Environment.GetEnvironmentVariable("SQLCONNSTR_SqlConnectionString");

        if (string.IsNullOrEmpty(connectionString))
        {
            log.LogError("A string de conex�o com o banco de dados est� vazia ou n�o foi definida.");
            return new ObjectResult(new { error = "A string de conex�o com o banco de dados est� vazia." })
            {
                StatusCode = StatusCodes.Status500InternalServerError
            };
        }
        else
        {
            log.LogInformation($"String de conex�o obtida: {connectionString}");
        }


        try
        {
            log.LogInformation("Tentando conectar ao banco de dados...");
            using (SqlConnection conn = new SqlConnection(connectionString))
            {
                await conn.OpenAsync();
                log.LogInformation("Conex�o com o banco de dados estabelecida com sucesso.");

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

                            var customer = new
                            {
                                Id = reader["Id"],
                                Name = reader["Name"],
                                Email = reader["Email"],
                                Cpf = reader["Cpf"]
                            };
                            return new OkObjectResult(customer);
                        }
                    }
                }

                if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(email))
                {
                    log.LogWarning("Nome ou email ausentes para o cadastro de um novo usu�rio.");
                    return new BadRequestObjectResult(new { error = "Nome e Email s�o obrigat�rios para novos usu�rios." });
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

                return new OkObjectResult(new { Message = "Usu�rio registrado com sucesso." });
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
