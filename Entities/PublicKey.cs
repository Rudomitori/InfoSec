using Microsoft.EntityFrameworkCore;

namespace InfoSec.Entities;

[Owned]
public record PublicKey
{
    public byte[] E { get; init; }
    public byte[] N { get; init; }
}