using System;
using System.Linq;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using PDFOnlineSignature.Models;

namespace PDFOnlineSignature.Data
{
    public static class DbInitializer
    {
        public static void Initialize(PDFOnlineSignatureContext context)
        {
            return;   // DB has been seeded
        }
    }
}