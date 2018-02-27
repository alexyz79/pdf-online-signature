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
using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using PDFOnlineSignature;
using PDFOnlineSignature.Models;
using PDFOnlineSignature.Core;
using PDFOnlineSignature.Core.Trust;

namespace PDFOnlineSignature.Core.Trust.Authentication
{
    internal class CertificateAuthenticationHandler : AuthenticationHandler<CertficateAuthenticationOptions>
    {
        PDFOnlineSignatureContext _context;
        IConfiguration _configuration;

        public CertificateAuthenticationHandler(IConfiguration configuration, PDFOnlineSignatureContext context, IOptionsMonitor<CertficateAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder, IDataProtectionProvider dataProtection, ISystemClock clock)
            : base(options, logger, encoder, clock)
        { 
            _context = context;
            _configuration = configuration;
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var certificate = Context.Connection.ClientCertificate;

            if ( certificate == null )
                return Task.FromResult(AuthenticateResult.Fail("Invalid Client Certificate"));

            if ( certificate.NotAfter < DateTime.Now ) {
                return Task.FromResult(AuthenticateResult.Fail("Certificate Expired or not ready for use"));
            }

            if ( certificate.SerialNumber == Program.AdministratorCertificate.SerialNumber ) {

                /* System Administrator Certificate */
                if ( !certificate.RawData.SequenceEqual(Program.AdministratorCertificate.RawData))
                    return Task.FromResult(AuthenticateResult.Fail("Invalid System Administrator Certificate"));

                var claims = new List<Claim>();
                claims.Add(new Claim(ClaimTypes.Role, "Admin"));
                claims.Add(new Claim(ClaimTypes.Role, "Operator"));
                claims.Add(new Claim(ClaimTypes.Role, "Reviewer"));

                var userIdentity = new ClaimsIdentity( claims, Options.Challenge);
                var userPrincipal = new ClaimsPrincipal(userIdentity);
                var ticket = new AuthenticationTicket(userPrincipal, new AuthenticationProperties(), Options.Challenge);
                
                return Task.FromResult(AuthenticateResult.Success(ticket));         

            } else {
                /* User Created Certificates  */
                var dbcert = _context.Certificate
                        .SingleOrDefault(m => m.SerialNumber == certificate.SerialNumber);

                if ( dbcert == null )
                    return Task.FromResult(AuthenticateResult.Fail("Invalid Client Certificate"));

                var x509cert = TrustManager.LoadCertificate(
                                                            dbcert.Uuid, 
                                                            null, 
                                                            CertificateType.ReviewerCertificate,
                                                            StoreFormat.DER );

                if ( x509cert.Thumbprint == certificate.Thumbprint ) {

                    var reviewer = _context.Reviewer.SingleOrDefault( m => m.Uuid == dbcert.ReviewerUuid );

                    if ( reviewer == null )
                        return Task.FromResult(AuthenticateResult.Fail("Wrong credentials"));
                        
                    var claims = new List<Claim>();
            
                    if ( reviewer.Role == "Admin" ) {
                        claims.Add(new Claim(ClaimTypes.Role, "Admin"));
                        claims.Add(new Claim(ClaimTypes.Role, "Operator"));
                        claims.Add(new Claim(ClaimTypes.Role, "Reviewer"));
                    } else if ( reviewer.Role == "Operator" ) {
                        claims.Add(new Claim(ClaimTypes.Role, "Operator"));
                        claims.Add(new Claim(ClaimTypes.Role, "Reviewer"));
                    } else if ( reviewer.Role == "Reviewer" ) {
                        claims.Add(new Claim(ClaimTypes.Role, "Reviewer"));
                    } else 
                        return Task.FromResult(AuthenticateResult.Fail("Wrong credentials"));              

                    var userIdentity = new ClaimsIdentity( claims, Options.Challenge);
                    var userPrincipal = new ClaimsPrincipal(userIdentity);
                    var ticket = new AuthenticationTicket(userPrincipal, new AuthenticationProperties(), Options.Challenge);
                    return Task.FromResult(AuthenticateResult.Success(ticket));         
                }
            }

            return Task.FromResult(AuthenticateResult.Fail("Wrong credentials"));
        }        
    }
}