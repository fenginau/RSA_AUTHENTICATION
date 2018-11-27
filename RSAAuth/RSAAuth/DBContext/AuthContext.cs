using Microsoft.EntityFrameworkCore;
using RSAAuth.Models;

namespace RSAAuth.DBContext
{
    internal class AuthContext : DbContext
    {
        public virtual DbSet<RsaRecordModel> RsaRecord { get; set; }
        public virtual DbSet<UserModel> User { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            if (!optionsBuilder.IsConfigured)
            {
                optionsBuilder.UseSqlServer(AppSettings.ConnectionString);
            }
        }
    }
}
