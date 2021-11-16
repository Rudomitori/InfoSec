using System;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace InfoSec.RestApi.Dtos.Input
{
    public class SignDto
    {
        [BindRequired] public Guid KeyPairId { get; set; }
        [BindRequired] public IFormFile File { get; set; }
    }
}