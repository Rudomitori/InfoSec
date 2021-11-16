using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace InfoSec.RestApi.Dtos.Input
{
    public class AddKeyPairDto
    {
        [BindRequired] public string Name { get; set; }
        [BindRequired] public IFormFile PublicKey { get; set; }
        [BindRequired] public IFormFile PrivateKey { get; set; }
    }
}