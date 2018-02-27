/*
  Copyright 2018 Alexandre Pires - c.alexandre.pires@gmail.com

  Permission is hereby granted, free of charge, to any person obtaining a copy of this 
  software and associated documentation files (the "Software"), to deal in the Software 
  without restriction,  including without  limitation the  rights to use, copy, modify, 
  merge,  publish, distribute,  sublicense, and/or sell  copies of the Software, and to 
  permit persons to whom the Software  is furnished  to do so, subject to the following 
  conditions:

  The above copyright notice and this permission notice shall be included in all copies
  or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS",  WITHOUT WARRANTY OF  ANY KIND, EXPRESS OR IMPLIED, 
  INCLUDING  BUT  NOT  LIMITED TO  THE WARRANTIES  OF  MERCHANTABILITY,  FITNESS  FOR A 
  PARTICULAR PURPOSE AND  NONINFRINGEMENT.  IN NO  EVENT SHALL THE AUTHORS OR COPYRIGHT 
  HOLDERS BE LIABLE FOR ANY CLAIM,  DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF 
  CONTRACT, TORT OR  OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE 
  OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
using System.IO;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;

namespace PDFOnlineSignature.Models {

 public class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<PDFOnlineSignatureContext>
{
    public PDFOnlineSignatureContext CreateDbContext(string[] args)
    {
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.Development.json")
            .Build();
 
        var builder = new DbContextOptionsBuilder<PDFOnlineSignatureContext>();
 
        string DataSource = "Data Source="+configuration["PDFOnlineSignature:DataSource"];

        if ( configuration["PDFOnlineSignature:DatabaseDriver"] == "SqlLite" ) {
            builder.UseSqlite(DataSource);
        }

        return new PDFOnlineSignatureContext(builder.Options);
    }
}   
    public class PDFOnlineSignatureContext : DbContext {
        public PDFOnlineSignatureContext (DbContextOptions<PDFOnlineSignatureContext> options):
            base (options) {

            }
        public DbSet<Document> Document { get; set; }
        public DbSet<Certificate> Certificate { get; set; }
        public DbSet<CertificateRequest> CertificateRequest { get; set; }
        public DbSet<Reviewer> Reviewer { get; set; }
        protected override void OnModelCreating (ModelBuilder modelBuilder) {
            modelBuilder.Entity<Reviewer> ()
                .HasAlternateKey (c => c.Email)
                .HasName ("UK_ReviewerEmail");
        }
    }
}