using System.IO;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Threading.Tasks;

public static class ValidateCPF
{
    [FunctionName("ValidateCPF")]
    public static async Task<IActionResult> Run(
        [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
        ILogger log)
    {
        log.LogInformation("Processando a requisição para validação de CPF.");

        string cpf = req.Query["cpf"];

        if (string.IsNullOrEmpty(cpf))
        {
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JsonConvert.DeserializeObject(requestBody);
            cpf = cpf ?? data?.cpf;
        }

        if (string.IsNullOrEmpty(cpf) || cpf.Length != 11)
        {
            return new BadRequestObjectResult("CPF inválido. O CPF deve conter 11 dígitos.");
        }

        return new OkObjectResult($"CPF válido: {cpf}");
        //Testando pipeline de CI/ CD
    }
}
