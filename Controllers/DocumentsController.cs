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
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using PDFOnlineSignature.Core;
using PDFOnlineSignature.Core.Render;
using PDFOnlineSignature.Core.Trust;
using PDFOnlineSignature.Core.Trust.Signature;
using PDFOnlineSignature.Models;
using Attachment = FluentEmail.Core.Models.Attachment;

namespace PDFOnlineSignature.Controllers {
    public class DocumentsController : Controller {
        private readonly PDFOnlineSignatureContext DBContext;
        private readonly IConfiguration Configuration;
        private readonly IViewRenderService RenderService;

        public DocumentsController (PDFOnlineSignatureContext context, IConfiguration configuration, IViewRenderService viewRenderService) {
            DBContext = context;
            Configuration = configuration;
            RenderService = viewRenderService;
        }

        [Authorize (Policy = "CanAccessReviewerMethods")]
        public IActionResult Sign () {
            ViewData["DocumentAction"] = "Sign";
            return View ("DocumentUpload");
        }

        public IActionResult Verify () {
            ViewData["DocumentAction"] = "Verify";
            return View ("DocumentUpload");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Upload (IFormFile upload, string documentaction) {

            Document document = await FileManager.StoreFile (upload);

            if (document == null) {
                return View ("InvalidDocument");
            }

            if (documentaction == "Sign") {

                var x509certificate = HttpContext.Connection.ClientCertificate;

                if (x509certificate == null) {
                    return View ("OperationNotAllowed");
                }

                var certificate = await DBContext.Certificate.
                SingleOrDefaultAsync (r => r.SerialNumber == x509certificate.SerialNumber);

                if (certificate == null) {
                    return View ("OperationNotAllowed");
                }

                if (certificate.ExpireDate < DateTime.Now) {
                    certificate.Revoked = true;
                    certificate.RevokeDate = DateTime.UtcNow.Date;
                    DBContext.Certificate.Update (certificate);
                    await DBContext.SaveChangesAsync ();
                }

                if (certificate.ExpireDate < DateTime.Now || certificate.Revoked == true) {
                    return RedirectToAction ("CertificateExpired", "Certificates");
                }

                document.ReviewerUuid = certificate.ReviewerUuid;
                document.Reviewer = certificate.Reviewer;
                document.Signed = false;

                DBContext.Add (document);
                await DBContext.SaveChangesAsync ();

                return View ("DocumentSign", document);
            } else if (documentaction == "Verify") {

                DBContext.Add (document);
                await DBContext.SaveChangesAsync ();

                return RedirectToAction ("VerifyDocument", new { uuid = document.Uuid });
            }

            return View ("OperationNotAllowed");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize (Policy = "CanAccessReviewerMethods")]
        public async Task<IActionResult> Sign (string uuid, string password, string description) {

            if (string.IsNullOrEmpty (uuid) || string.IsNullOrEmpty (password)) {
                return View ("OperationNotAllowed");
            }

            var document = await DBContext.Document
                .SingleOrDefaultAsync (m => m.Uuid == uuid);

            if (document == null) {
                return NotFound ();
            }

            if (document.MimeType != "application/pdf") {
                return View ("InvalidDocument");
            }

            var x509certificate = HttpContext.Connection.ClientCertificate;

            if (x509certificate == null) {
                return View ("OperationNotAllowed");
            }

            var certificate = await DBContext.Certificate
                .SingleOrDefaultAsync (r => r.SerialNumber == x509certificate.SerialNumber);

            if (certificate == null || certificate.ReviewerUuid != document.ReviewerUuid) {
                return View ("OperationNotAllowed");
            }

            if (certificate.ExpireDate < DateTime.Now.Date) {
                certificate.Revoked = true;
                certificate.RevokeDate = DateTime.UtcNow.Date;
                DBContext.Certificate.Update (certificate);
                await DBContext.SaveChangesAsync ();
            }

            if (certificate.Revoked == true) {
                return RedirectToAction ("CertificateExpired", "Certificates");
            }

            var pkcs12store = TrustManager.LoadPkcs12Store (certificate.Uuid, password, CertificateType.ReviewerCertificate);

            if (pkcs12store == null) {
                return View ("OperationNotAllowed");
            }

            var reviewer = await DBContext.Reviewer
                .SingleOrDefaultAsync (r => r.Uuid == certificate.ReviewerUuid);

            var metadata = new PDFMetadata () {
                Title = "PDF Signed Document" + document.Name,
                Author = certificate.Reviewer.Name,
                Creator = certificate.Reviewer.Name,
                Producer = certificate.Reviewer.Name,
                Keywords = "UUID:" + document.Uuid,
                Subject = "Signed Document"
            };

            var signature = new Signature () {
                Store = pkcs12store,
                Reason = "Document Aproved, Date:" + DateTime.UtcNow.Date,
                Page = 1,
                Contact = certificate.Reviewer.Email,
                CustomText = "Signed by "+ reviewer.Name + " on " + DateTime.UtcNow.Date.ToString ("dd-MM-yyyy") + " - " + description,
                Top = 10,
                Left = 10,
                Width = 200,
                Height = 50,                

                Multi = false,
                Visible = true
            };

            SignatureManager.Sign (
                signature,
                metadata,
                FileManager.DocumentRoot + "/" + document.Uuid,
                FileManager.DocumentRoot + "/" + document.Uuid + "-signed");

            document.SignatureDate = DateTime.UtcNow.Date;
            DBContext.Document.Update (document);
            await DBContext.SaveChangesAsync ();

            var message = await RenderService
                .RenderToStringAsync ("Email/DocumentSigned", document);
            var attachments = new List<Attachment> ();

            attachments.Add (
                await EmailManager.LoadAttachment (
                    FileManager.DocumentRoot + "/" + document.Uuid + "-signed",
                    "Signed by " + reviewer.Name + "-" + document.Name,
                    document.MimeType));

            attachments.Add (
                await EmailManager.LoadAttachment (
                    TrustManager.CertificatePath (
                        certificate.Uuid,
                        CertificateType.ReviewerCertificate,
                        StoreFormat.CRT),
                    "public.crt",
                    "application/x-x509-ca-cert"));

            attachments.Add (
                await EmailManager.LoadAttachment (
                    TrustManager.CertificatePath (
                        "root",
                        CertificateType.AuthorityCertificate,
                        StoreFormat.CRT),
                    "authority.crt",
                    "application/x-x509-ca-cert"));

            var response = await EmailManager.SendEmailHTML (
                message,
                EmailManager.Sender,
                certificate.Reviewer.Email,
                "Your signed document is ready",
                attachments
            );

            if (!response.Successful)
                return View ("ErrorSendingDocument", document);

            return View ("DocumentSigned", document);
        }

        public async Task<IActionResult> VerifyDocument (string uuid) {

            if (string.IsNullOrEmpty (uuid)) {
                return NotFound ();
            }

            var document = await DBContext.Document
                .SingleOrDefaultAsync (m => m.Uuid == uuid);

            if (document == null) {
                return NotFound ();
            }

            var certificates = await DBContext.Certificate.ToListAsync ();
            var signatureValidations = new List<SignatureValidation> ();

            foreach (var certificate in certificates) {

                var x509certificate = TrustManager.LoadX509Certificate (
                    certificate.Uuid,
                    CertificateType.ReviewerCertificate);

                SignatureValidation result = SignatureManager.VerifySignature (x509certificate, FileManager.DocumentRoot + "/" + document.Uuid);

                if (result != null) {

                    result.SignatureName = certificate.ReviewerName;
                    result.Certificate = certificate;
                    if (certificate.Revoked == true && result.SignatureDate > certificate.RevokeDate) {
                        result.SignatureRevoked = true;
                    } else if (certificate.Revoked != true && result.SignatureDate > certificate.ExpireDate) {
                        result.SignatureExpired = true;
                    }
                    signatureValidations.Add (result);
                }
            }

            DBContext.Document.Remove(document);
            DBContext.SaveChanges();

            return View ("DocumentResult", signatureValidations);
        }

        [Authorize (Policy = "CanAccessReviewerMethods")]
        public async Task<IActionResult> Download (string uuid) {

            if (string.IsNullOrEmpty (uuid)) {
                return NotFound ();
            }

            var document = await DBContext.Document
                .SingleOrDefaultAsync (m => m.Uuid == uuid);

            if (document == null) {
                return NotFound ();
            }

            var memory = await FileManager.GetFile(document);
            return File (memory, document.MimeType, document.Name);
        }
    }
}