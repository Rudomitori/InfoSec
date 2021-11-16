using System;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace InfoSec.RestApi.Dtos.Input
{
    public class RenameKeyPairDto
    {
        [BindRequired]
        [FromRoute]
        public Guid Id { get; set; }
        
        [BindRequired]
        [FromBody]
        public string Name { get; set; }
    }
}