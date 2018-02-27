using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Org.BouncyCastle.Asn1.X509;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using System.Security.Authentication;
using PDFOnlineSignature.Core;
using PDFOnlineSignature.Core.Trust;

namespace PDFOnlineSignature
{
    public class Program
    {
        internal static string Environment = null;
        internal static IConfigurationRoot Configuration = null;
        internal static X509Certificate2 ServerCertificate = null;
        internal static DistinguishedName ServerDN = null;
        internal static X509Certificate2 AdministratorCertificate = null;
        internal static DistinguishedName AdministratorDN = null;
        internal static string Hostname { 
            get {
                return Configuration.GetValue<string>("PDFOnlineSignature:Hostname","localhost");
            }
        }
        internal static int Port { 
            get {
                return Configuration.GetValue<int>("PDFOnlineSignature:Port",5000);
            }
        }        public static void Main(string[] args)
        {
            var build = WebHost.CreateDefaultBuilder(args);            
     
            Environment = build.GetSetting("environment");
            
            var builder  = new ConfigurationBuilder()
                                    .SetBasePath(Directory.GetCurrentDirectory())
                                    .AddJsonFile($"appsettings.{Environment}.json", optional: false);
            
            Configuration = builder.Build();
            TrustManager.Init(Configuration);
            EmailManager.Init(Configuration);
            FileManager.Init(Configuration);

            DateTime now = DateTime.UtcNow.Date;

            if ( !TrustManager
                        .CertificateAvailable(
                            "webserver",CertificateType.ServerCertificate,StoreFormat.PFX)) {
                
                ServerDN = new DistinguishedName();

                ServerDN.CommonName = Configuration["WebServer:ServerCertificate:CommonName"];
                ServerDN.Organization = Configuration["WebServer:ServerCertificate:Org"];
                ServerDN.OrganizationalUnit = Configuration["WebServer:ServerCertificate:OrgUnit"];
                ServerDN.Locality = Configuration["WebServer:ServerCertificate:Locality"];
                ServerDN.Country = Configuration["WebServer:ServerCertificate:Country"];
                ServerDN.State = Configuration["WebServer:ServerCertificate:State"];
                ServerDN.Email = Configuration["WebServer:ServerCertificate:Email"];                
                
                ServerCertificate = TrustManager.IssueCertificate(
                                                                "webserver", 
                                                                Configuration["WebServer:ServerCertificate:Password"],
                                                                ServerDN,
                                                                CertificateType.ServerCertificate,
                                                                now,
                                                                now.AddYears(50));
            } else {
                ServerCertificate = TrustManager.LoadCertificate(
                                                                "webserver",
                                                                Configuration["WebServer:ServerCertificate:Password"],
                                                                CertificateType.ServerCertificate,
                                                                StoreFormat.PFX);
            }

            if ( !TrustManager
                        .CertificateAvailable(
                            "administrator",CertificateType.AdministratorCertificate,StoreFormat.PFX)) {
                
                AdministratorDN = new DistinguishedName();

                AdministratorDN.CommonName = Configuration["WebServer:AdministratorCertificate:CommonName"];
                AdministratorDN.Organization = Configuration["WebServer:AdministratorCertificate:Org"];
                AdministratorDN.OrganizationalUnit = Configuration["WebServer:AdministratorCertificate:OrgUnit"];
                AdministratorDN.Locality = Configuration["WebServer:AdministratorCertificate:Locality"];
                AdministratorDN.Country = Configuration["WebServer:AdministratorCertificate:Country"];
                AdministratorDN.State = Configuration["WebServer:AdministratorCertificate:State"];
                AdministratorDN.Email = Configuration["WebServer:AdministratorCertificate:Email"];                
                
                AdministratorCertificate = 
                            TrustManager.IssueCertificate(
                                                        "administrator", 
                                                        Configuration["WebServer:AdministratorCertificate:Password"],
                                                        AdministratorDN,
                                                        CertificateType.AdministratorCertificate,
                                                        now,
                                                        now.AddYears(50));
            } else {
                AdministratorCertificate = 
                            TrustManager.LoadCertificate(
                                                        "administrator", 
                                                        Configuration["WebServer:AdministratorCertificate:Password"],
                                                        CertificateType.AdministratorCertificate,
                                                        StoreFormat.PFX);
            }

           var host = build
                .UseKestrel(options => {
                    options.Listen(IPAddress.Any, Port, 
                                        listenOptions => {
                                            var httpsConnectionAdapterOptions = new HttpsConnectionAdapterOptions()
                                            {
                                                ClientCertificateMode = ClientCertificateMode.AllowCertificate,
                                                ClientCertificateValidation = delegate(X509Certificate2 certificate,X509Chain chain, SslPolicyErrors sslPolicyErrors){ 
                                                    return true; 
                                                },
                                                SslProtocols = SslProtocols.Tls | SslProtocols.Tls11 | SslProtocols.Tls12 ,
                                                ServerCertificate = Program.ServerCertificate
                                            };
                                            listenOptions.UseHttps(httpsConnectionAdapterOptions);
                                        });
                                }
                ) 
                .UseStartup<Startup>()
                .UseIISIntegration()
                .Build();
                host.Run();
        }
    }
}
