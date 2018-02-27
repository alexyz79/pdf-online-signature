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
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Authorization;
using PDFOnlineSignature.Core;
using PDFOnlineSignature.Core.Render;
using PDFOnlineSignature.Models;
using PDFOnlineSignature.Core.Trust;
using PDFOnlineSignature.Core.Trust.Signature;
using Attachment = FluentEmail.Core.Models.Attachment;

namespace PDFOnlineSignature.Controllers {
    public class DocumentsController : Controller {
        private readonly PDFOnlineSignatureContext _context;
        private readonly IConfiguration _configuration;
        private readonly IViewRenderService _renderService;

        public DocumentsController (PDFOnlineSignatureContext context, IConfiguration cfg, IViewRenderService viewRenderService) {
            _context = context;
            _configuration = cfg;
            _renderService = viewRenderService;
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

            var x509cert = HttpContext.Connection.ClientCertificate;

            var cert = await _context.Certificate.
            Include (r => r.Reviewer).
            SingleOrDefaultAsync (r => r.SerialNumber == x509cert.SerialNumber);

            if (cert == null) {
                return NotFound ();
            }

            if (cert.ExpireDate < DateTime.Now || cert.Revoked == true) {
                return RedirectToAction ("CertificateExpired", "Certificates");
            }

            string uploadFolder = FileManager.DocumentRoot;

            DateTime timestamp = DateTime.UtcNow.Date;
            Guid unique_id = Guid.NewGuid ();

            using (var stream = new FileStream (uploadFolder + "/" + unique_id.ToString (), FileMode.Create)) {
                await upload.CopyToAsync (stream);
            }

            Document document = new Document ();
            document.Uuid = unique_id.ToString ();
            document.Name = upload.FileName;
            document.Size = upload.Length;
            document.ReviewerUuid = cert.ReviewerUuid;
            document.Reviewer = cert.Reviewer;
            document.CreationdDate = timestamp;
            document.MimeType = "application/pdf";
            document.Signed = false;

            _context.Add (document);
            await _context.SaveChangesAsync ();

            if (documentaction == "Sign") {
                return View ("DocumentSign", document);
            }

            return RedirectToAction ("VerifyDocument", new { uuid = document.Uuid });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize (Policy = "CanAccessReviewerMethods")]
        public async Task<IActionResult> Sign (string uuid, string password, string description) {

            if (string.IsNullOrEmpty (uuid)) {
                return NotFound ();
            }

            var document = await _context.Document.
            SingleOrDefaultAsync (m => m.Uuid == uuid);

            if (document == null) {
                return NotFound ();
            }

            if (document.MimeType != "application/pdf") {
                return View ("InvalidFile");
            }

            var x509cert = HttpContext.Connection.ClientCertificate;

            var cert = await _context.Certificate.
            Include (r => r.Reviewer).
            SingleOrDefaultAsync (r => r.SerialNumber == x509cert.SerialNumber);

            if (cert == null || cert.ReviewerUuid != document.ReviewerUuid) {
                return NotFound ();
            }

            if (cert.ExpireDate < DateTime.Now || cert.Revoked == true) {
                return RedirectToAction ("CertificateExpired", "Certificates");
            }

            string uploadFolder = FileManager.DocumentRoot;

            var metadata = new PDFMetadata ();
            metadata.Title = "PDF Signed Document" + document.Name;
            metadata.Author = cert.Reviewer.Name;
            metadata.Creator = cert.Reviewer.Name;
            metadata.Producer = cert.Reviewer.Name;
            metadata.Keywords = "UUID:" + document.Uuid;
            metadata.Subject = "Signed Document";

            var signature = new Signature ();
            signature.Store = TrustManager.LoadP12Store (cert.Uuid, password, CertificateType.ReviewerCertificate);
            signature.Reason = "Document Aproved, Date:" + DateTime.UtcNow.Date;
            signature.Page = 1;
            signature.Contact = cert.Reviewer.Email;
            signature.CustomText = "Aproved by " + cert.Reviewer.Name + " - Date:" + DateTime.UtcNow.Date.ToString () + " - " + description;
            signature.Top = 10;
            signature.Left = 10;
            signature.Width = 200;
            signature.Height = 50;
            signature.Multi = false;
            signature.Visible = true;

            SignatureManager.Sign (
                signature,
                metadata,
                uploadFolder + "/" + document.Uuid,
                uploadFolder + "/" + document.Uuid + "-signed");

            document.SignatureDate = DateTime.UtcNow.Date;
            _context.Document.Update (document);
            await _context.SaveChangesAsync ();

            var message = await _renderService.RenderToStringAsync ("Email/DocumentSigned", document);
            var attachments = new List<Attachment> ();

            attachments.Add (
                await EmailManager.LoadAttachment (
                    uploadFolder + "/" + document.Uuid + "-signed",
                    document.Name,
                    document.MimeType));

            attachments.Add (
                await EmailManager.LoadAttachment (
                    TrustManager.CertificatePath (
                        cert.Uuid,
                        CertificateType.ReviewerCertificate,
                        StoreFormat.DER),
                    "public.crt",
                    "application/x-x509-ca-cert"));

            attachments.Add (
                await EmailManager.LoadAttachment (
                    TrustManager.CertificatePath (
                        "root",
                        CertificateType.AuthorityCertificate,
                        StoreFormat.DER),
                    "authority.crt",
                    "application/x-x509-ca-cert"));

            var response = await EmailManager.SendEmailHTML (
                message,
                EmailManager.Sender,
                cert.Reviewer.Email,
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

            var document = await _context.Document.
            SingleOrDefaultAsync (m => m.Uuid == uuid);

            if (document == null) {
                return NotFound ();
            }

            string uploadFolder = FileManager.DocumentRoot;

            var certs = _context.Certificate.
            Include (r => r.Reviewer);

            var validReviews = new List<SignatureValidation> ();

            foreach (var cert in certs) {

                var x509cert = TrustManager.LoadX509Certificate (
                    cert.Uuid,
                    CertificateType.ReviewerCertificate);

                SignatureValidation result = SignatureManager.VerifySignature (x509cert, uploadFolder + "/" + document.Uuid);

                if (result != null) {

                    result.SignatureName = cert.Reviewer.Name;
                    if (cert.Revoked == true && result.SignatureDate < cert.RevokeDate) {
                        validReviews.Add (result);
                    } else if (cert.Revoked != true && result.SignatureDate < cert.ExpireDate) {
                        validReviews.Add (result);
                    }
                }
            }

            return View ("DocumentResult", validReviews);
        }

        [Authorize (Policy = "CanAccessReviewerMethods")]
        public async Task<IActionResult> Download (string uuid) {
           
            string uploadFolder = FileManager.DocumentRoot;

            if (string.IsNullOrEmpty (uuid)) {
                return NotFound ();
            }

            var document = await _context.Document.
            SingleOrDefaultAsync (m => m.Uuid == uuid);

            if (document == null) {
                return NotFound ();
            }

            string path = uploadFolder + "/" + document.Uuid;

            if (document.Signed == true) {
                path += "-signed";
            }

            var memory = new MemoryStream ();

            using (var stream = new FileStream (path, FileMode.Open)) {
                await stream.CopyToAsync (memory);
            }

            memory.Position = 0;

            return File (memory, document.MimeType, document.Name);
        }
    }
}