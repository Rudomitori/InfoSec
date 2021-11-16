using InfoSec.Entities;
using Microsoft.EntityFrameworkCore;

namespace InfoSec
{
    public class AppDbContext: DbContext
    {
        public DbSet<User> Users { get; set; }
        public DbSet<KeyPair> KeyPairs { get; set; }
        
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
            Database.EnsureCreated();
        }
    }
}