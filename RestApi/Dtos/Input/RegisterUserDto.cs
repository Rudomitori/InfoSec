using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace InfoSec.RestApi.Dtos.Input
{
    public class RegisterUserDto
    {
        [BindRequired] public string Login { get; set; }
        [BindRequired] public string Password { get; set; }
    }
}