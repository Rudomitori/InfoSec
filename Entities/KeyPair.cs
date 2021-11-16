using System;
using System.ComponentModel.DataAnnotations;

namespace InfoSec.Entities
{
    public class KeyPair
    {
        public Guid Id { get; set; }
        [Required] public string Name { get; set; }
        [Required] public byte[] PublicKey { get; set; }
        [Required] public byte[] PrivateKey { get; set; }
        
        public Guid OwnerId { get; set; }
        public User Owner { get; set; }
    }
}