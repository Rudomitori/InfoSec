using System;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace InfoSec.RestApi.Dtos.Input
{
    public class CheckSignDto
    {
        [BindRequired] public IFormFile File { get; set; }
        [BindRequired] public IFormFile SignFile { get; set; }
        // Не знаю, достаточно ли будет файла с подписью,
        // чтобы получить из базы нужный публичный ключ,
        // поэтому проще явно указывать, какой ключ нужен
        [BindRequired] public Guid KeyPairId { get; set; }
    }
}