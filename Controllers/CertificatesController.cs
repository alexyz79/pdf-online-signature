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
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Authorization;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Security;
using PDFOnlineSignature.Core;
using PDFOnlineSignature.Core.Render;
using PDFOnlineSignature.Models;
using PDFOnlineSignature.Core.Trust;
using Attachment = FluentEmail.Core.Models.Attachment;

namespace PDFOnlineSignature.Controllers {
    public class CertificatesController : Controller {

        private readonly PDFOnlineSignatureContext _context;
        private readonly IConfiguration _configuration;
        private readonly IViewRenderService _renderService;
        public CertificatesController (PDFOnlineSignatureContext context, IConfiguration cfg, IViewRenderService viewRenderService) {
            _context = context;
            _configuration = cfg;
            _renderService = viewRenderService;
        }

        [Authorize (Policy = "CanAccessOperatorMethods")]
        public async Task<IActionResult> Index () {
            return View (await _context.Certificate.ToListAsync ());
        }

        [ActionName ("Request")]
        [Authorize (Policy = "CanAccessOperatorMethods")]
        public async Task<IActionResult> RequestCert (string reviewerUuid) {

            if (string.IsNullOrEmpty (reviewerUuid)) {
                return NotFound ();
            }

            var reviewer = await _context.Reviewer
                .SingleOrDefaultAsync (m => m.Uuid == reviewerUuid);

            if (reviewer == null) {
                return NotFound ();
            }

            if (reviewer.Certificate != null) {

                if (reviewer.Certificate.Revoked != true && reviewer.Certificate.ExpireDate > DateTime.Now) {
                    return RedirectToAction (nameof (CertificateExists));
                }

                reviewer.Certificate.Revoked = true;
                _context.Certificate.Update (reviewer.Certificate);
                await _context.SaveChangesAsync ();

                reviewer.Certificate = null;
                _context.Reviewer.Update (reviewer);
                await _context.SaveChangesAsync ();
            }

            CryptoApiRandomGenerator randomGenerator = new CryptoApiRandomGenerator ();
            SecureRandom random = new SecureRandom (randomGenerator);

            CertificateRequest cr = new CertificateRequest {
                Uuid = Guid.NewGuid ().ToString (),
                ReviewerUuid = reviewerUuid,
                Reviewer = reviewer,
                RequestDate = DateTime.Now,
                SecurityCode = random.Next (10000000, 99999999).ToString ()
            };

            await _context.CertificateRequest.AddAsync (cr);
            await _context.SaveChangesAsync ();

            var message = await _renderService.RenderToStringAsync ("Email/CertificateRequest", cr);
            var response = await EmailManager.SendEmailHTML (
                message,
                EmailManager.Sender,
                reviewer.Email,
                "Certificate Request Confirmation",
                null);

            if (!response.Successful)
                return View ("ErrorSendingRequest");

            ViewData["Hostname"] = Program.Hostname;
            ViewData["Port"] = Program.Port;
            return View ();
        }

        public async Task<IActionResult> Issue (string requestId) {

            if (string.IsNullOrEmpty (requestId)) {
                return NotFound ();
            }

            /* Clean up expi */
            var expiredcr = from b in _context.CertificateRequest
            where b.RequestDate < DateTime.Now.AddMinutes (-30) &&
                b.CertificateUuid == null
            select b;

            _context.CertificateRequest.RemoveRange (expiredcr);
            await _context.SaveChangesAsync ();

            var cr = await _context.CertificateRequest
                .Include (s => s.Reviewer)
                .SingleOrDefaultAsync (m => m.Uuid == requestId);

            if (cr == null) {
                return RedirectToAction (nameof (RequestExpired));
            }

            if (cr.RequestDate == null || string.IsNullOrEmpty (cr.SecurityCode)) {
                return RedirectToAction (nameof (RequestExpired));
            }

            if (cr.CertificateUuid != null) {
                return RedirectToAction (nameof (RequestExpired));
            }

            ViewData["Request"] = cr;
            return View ();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Issue (
            string requestId, string password, string code) {
            if (string.IsNullOrEmpty (requestId)) {
                return NotFound ();
            }

            var request = await _context.CertificateRequest
                .Include (s => s.Reviewer)
                .SingleOrDefaultAsync (m => m.Uuid == requestId);

            if (request == null) {
                return NotFound ();
            }

            if (code != request.SecurityCode) {
                return RedirectToAction ("RequestExpired");
            }

            var now = DateTime.UtcNow.Date;

            var certificate = new Certificate ();
            certificate.Uuid = Guid.NewGuid ().ToString ();
            certificate.CreationDate = now;
            certificate.ExpireDate = now.AddYears (1);
            certificate.Revoked = false;
            certificate.ReviewerUuid = request.ReviewerUuid;

            DistinguishedName dn = new DistinguishedName ();

            dn.CommonName = request.Reviewer.Name;
            dn.Email = request.Reviewer.Email;
            dn.Organization = TrustManager.IssuerDN.Organization;
            dn.OrganizationalUnit = TrustManager.IssuerDN.OrganizationalUnit;
            dn.Country = TrustManager.IssuerDN.Country;
            dn.Locality = TrustManager.IssuerDN.Locality;
            dn.State = TrustManager.IssuerDN.State;

            var x509cert = TrustManager.IssueCertificate (
                certificate.Uuid.ToString (),
                password,
                dn,
                CertificateType.ReviewerCertificate,
                now, now.AddYears (1));

            certificate.SerialNumber = x509cert.SerialNumber;

            _context.Add (certificate);
            await _context.SaveChangesAsync ();

            request.CertificateUuid = certificate.Uuid;
            request.Certificate = certificate;
            request.Reviewer.Certificate = certificate;

            _context.Update (request);
            await _context.SaveChangesAsync ();

            var message = await _renderService.RenderToStringAsync ("Email/CertificateIssued", request.Reviewer);
            var attachments = new List<Attachment> ();
            attachments.Add (
                await EmailManager.LoadAttachment (
                    TrustManager.CertificatePath (
                        certificate.Uuid,
                        CertificateType.ReviewerCertificate,
                        StoreFormat.P12Store), "private.p12", "application/x-pkcs12"));

            attachments.Add (
                await EmailManager.LoadAttachment (
                    TrustManager.CertificatePath (
                        certificate.Uuid,
                        CertificateType.ReviewerCertificate,
                        StoreFormat.DER), "public.crt", "application/x-x509-ca-cert"));

            attachments.Add (
                await EmailManager.LoadAttachment (
                    TrustManager.CertificatePath (
                        "root",
                        CertificateType.AuthorityCertificate,
                        StoreFormat.DER), "authority.crt", "application/x-x509-ca-cert"));

            var response = await EmailManager.SendEmailHTML (
                message, 
                EmailManager.Sender, 
                request.Reviewer.Email, 
                "Your new certificate is ready", 
                attachments
            );

            if (!response.Successful)
                return View ("ErrorSendingCertificate");

            return RedirectToAction (nameof (CertificateSent));
        }

        public IActionResult RequestExpired () {

            return View ();
        }

        public IActionResult CertificateExists () {

            return View ();
        }

        public IActionResult CertificateExpired () {

            return View ();
        }

        public IActionResult CertificateSent () {

            return View ();
        }

        [Authorize (Policy = "CanAccessAdminMethods")]
        public async Task<IActionResult> Revoke (string uuid) {
            if (string.IsNullOrEmpty (uuid)) {
                return NotFound ();
            }

            var certificate = await _context.Certificate
                .SingleOrDefaultAsync (m => m.Uuid == uuid && m.Revoked == false);

            if (certificate == null) {
                return NotFound ();
            }

            return View (certificate);
        }

        [HttpPost, ActionName ("Revoke")]
        [ValidateAntiForgeryToken]
        [Authorize (Policy = "CanAccessAdminMethods")]
        public async Task<IActionResult> RevokeConfirmed (string uuid) {
            var certificate = await _context.Certificate.SingleOrDefaultAsync (m => m.Uuid == uuid);

            certificate.Revoked = true;
            certificate.RevokeDate = DateTime.UtcNow.Date;
            _context.Certificate.Update (certificate);
            await _context.SaveChangesAsync ();

            return RedirectToAction (nameof (Index), "Home");
        }

        [Authorize (Policy = "CanAccessAdminMethods")]
        public async Task<IActionResult> DownloadP12Store (string uuid) {

            if (string.IsNullOrEmpty (uuid)) {
                return NotFound ();
            }

            var certificate = await _context.Certificate.
            SingleOrDefaultAsync (m => m.Uuid == uuid && m.Revoked == false);

            if (certificate == null) {
                return NotFound ();
            }

            if (certificate.Revoked == true || certificate.ExpireDate < DateTime.UtcNow.Date) {
                return NotFound ();
            }

            var memory = new MemoryStream ();
            using (var stream = new FileStream (
                TrustManager.CertificatePath (
                    certificate.Uuid,
                    CertificateType.ReviewerCertificate,
                    StoreFormat.P12Store), FileMode.Open)) {
                await stream.CopyToAsync (memory);
            }

            memory.Position = 0;

            return File (memory, "application/x-pkcs12", certificate.SerialNumber + ".p12");
        }

        [Authorize (Policy = "CanAccessReviewerMethods")]
        public async Task<IActionResult> DownloadPublicDER (string uuid) {

            if (string.IsNullOrEmpty (uuid)) {
                return NotFound ();
            }

            var certificate = await _context.Certificate.
            SingleOrDefaultAsync (m => m.Uuid == uuid && m.Revoked == false);

            if (certificate == null) {
                return NotFound ();
            }

            if (certificate.Revoked == true || certificate.ExpireDate < DateTime.UtcNow.Date) {
                return NotFound ();
            }

            var memory = new MemoryStream ();

            using (var stream = new FileStream (
                TrustManager.CertificatePath (
                    certificate.Uuid,
                    CertificateType.ReviewerCertificate,
                    StoreFormat.DER), FileMode.Open)) {
                await stream.CopyToAsync (memory);
            }

            memory.Position = 0;

            return File (memory, "application/x-x509-ca-cert", certificate.SerialNumber + ".der");
        }
    }
}