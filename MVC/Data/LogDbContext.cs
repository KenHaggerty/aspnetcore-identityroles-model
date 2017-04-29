using MVC.Models;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace MVC.Data
{
    public class LogDbContext : DbContext
    {
        
        public virtual DbSet<LogEntry> LogEntries { get; set; }
        
        public LogDbContext()
        {
            Database.EnsureCreated();
        }
        
        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            string connectionStringBuilder = new SqliteConnectionStringBuilder()
            {
                DataSource = "./app_data/MVC_EventLog.sqlite"
            }
            .ToString();

            var connection = new SqliteConnection(connectionStringBuilder);
            optionsBuilder.UseSqlite(connection);
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);            
        }
    }
}
