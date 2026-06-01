using System;

using Microsoft.EntityFrameworkCore;
using Websegura.Models;

namespace Websegura.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
        public DbSet<User> Users { get; set; }
    }
}