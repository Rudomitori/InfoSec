using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace InfoSec.Entities
{
    public class User
    {
        public Guid Id { get; set; }
        [Required] public string Login { get; set; }
        [Required] public string Password { get; set; }
        
        public IList<KeyPair> KeyPairs { get; set; }
    }
}