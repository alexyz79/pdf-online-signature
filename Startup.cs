using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Org.BouncyCastle.Asn1.X509;
using PDFOnlineSignature.Core.Render;
using PDFOnlineSignature.Models;
using PDFOnlineSignature.Core.Trust.Authentication;

namespace PDFOnlineSignature {
    public class Startup {
        public Startup (IConfiguration configuration) {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices (IServiceCollection services) {
            services.AddMvc ();

            string DataSource = "Data Source=" + Configuration["PDFOnlineSignature:DataSource"];

            if (Configuration["PDFOnlineSignature:DatabaseDriver"] == "SqlLite") {
                services.AddDbContext<PDFOnlineSignatureContext> (
                    options => options.UseSqlite (DataSource)
                );
            }

            // Add framework services.
            services.AddSingleton<IConfiguration> (Configuration);
            services.AddScoped<IViewRenderService, ViewRenderService> ();
            services.AddMvc ();
            services.AddAuthentication (options => {
                    options.DefaultAuthenticateScheme = CertificateAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = CertificateAuthenticationDefaults.AuthenticationScheme;
                })
                .AddCertificateAuthentication (certOptions => { });

            services.AddAuthorization (options => {
                options.AddPolicy ("CanAccessAdminMethods", policy => policy.RequireRole ("Admin"));
                options.AddPolicy ("CanAccessOperatorMethods", policy => policy.RequireRole ("Operator"));
                options.AddPolicy ("CanAccessReviewerMethods", policy => policy.RequireRole ("Reviewer"));
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure (IApplicationBuilder app, IHostingEnvironment env) {
            if (env.IsDevelopment ()) {
                app.UseDeveloperExceptionPage ();
            } else {
                app.UseExceptionHandler ("/Home/Error");
            }

            app.UseStaticFiles ();
            app.UseAuthentication ();
            app.UseMvc (routes => {
                routes.MapRoute (
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}