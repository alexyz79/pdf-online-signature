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
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using iTextSharp.text;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.crypto;
using iTextSharp.text.xml.xmp;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using X509Certificate2 = System.Security.Cryptography.X509Certificates.X509Certificate2;
using X509KeyStorageFlags = System.Security.Cryptography.X509Certificates.X509KeyStorageFlags;
using X509ContentType = System.Security.Cryptography.X509Certificates.X509ContentType;
using PDFOnlineSignature.Core.Trust;
using PDFOnlineSignature.Core.Trust.Signature;

namespace PDFOnlineSignature.Core {
    public static class SignatureManager {
        static readonly int ContentEstimated = 15000;

        static byte[] CreateMessageDigestHash (Stream data) {

            IDigest messageDigest = DigestUtilities.GetDigest ("SHA-256");
            byte[] buf = new byte[8192];
            int n;
            while ((n = data.Read (buf, 0, buf.Length)) > 0) {
                messageDigest.BlockUpdate (buf, 0, n);
            }

            byte[] hash = new byte[messageDigest.GetDigestSize ()];
            messageDigest.DoFinal (hash, 0);

            return hash;
        }

        static string GetPrivateKeyName (Pkcs12Store store) {
            var aliases = store.Aliases;

            foreach (string alias in aliases) {

                if (store.IsKeyEntry (alias) && store.GetKey (alias).Key.IsPrivate) {
                    return alias;
                }
            }

            return null;
        }

        static X509Certificate[] GetCertificateChain (Pkcs12Store store, string name) {

            X509CertificateEntry[] certificateEntries = store.GetCertificateChain (name);

            if (certificateEntries == null)
                return null;

            if (certificateEntries.Length == 0)
                return null;

            X509Certificate[] certificateChain = new X509Certificate[certificateEntries.Length];

            for (int k = 0; k < certificateEntries.Length; ++k)
                certificateChain[k] = certificateEntries[k].Certificate;

            return certificateChain;
        }
        static byte[] GetCertificateChainOCSP (X509Certificate[] certificateChain) {

            byte[] ocsp = null;

            if (certificateChain.Length >= 2) {
                String url = PdfPKCS7.GetOCSPURL (certificateChain[0]);
                if (url != null && url.Length > 0) {
                    ocsp = new OcspClientBouncyCastle (certificateChain[0], certificateChain[1], url).GetEncoded ();
                }
            }
            return ocsp;
        }

        static PdfSignatureAppearance CreateSignatureAppearance (PdfStamper stamper, Signature signature) {

            PdfSignatureAppearance signatureAppearance = stamper.SignatureAppearance;

            signatureAppearance.Reason = signature.Reason;
            signatureAppearance.Contact = signature.Contact;
            signatureAppearance.Location = signature.Location;
            signatureAppearance.SignDate = DateTime.UtcNow.Date;

            if (signature.Visible) {

                iTextSharp.text.Rectangle rect = stamper.Reader.GetPageSize (signature.Page);

                if (signature.RawData != null)
                    signatureAppearance.Image = iTextSharp.text.Image.GetInstance (signature.RawData);

                signatureAppearance.Layer2Text = signature.CustomText;

                signatureAppearance.SetVisibleSignature (new iTextSharp.text.Rectangle (
                    signature.Left,
                    signature.Top,
                    signature.Left + signature.Width,
                    signature.Top + signature.Height), signature.Page, null);
            }

            return signatureAppearance;
        }

        static void PKCS7SignDocument (

            AsymmetricKeyParameter privateKey,
            X509Certificate[] certificateChain,
            byte[] hash, byte[] ocsp,
            PdfSignatureAppearance signatureAppearance) {

            DateTime timestamp = signatureAppearance.SignDate;
            PdfPKCS7 pdfPKCS7signature = new PdfPKCS7 (privateKey, certificateChain, null, "SHA-256", false);
            byte[] authAttributeBytes = pdfPKCS7signature.GetAuthenticatedAttributeBytes (hash, timestamp, ocsp);
            pdfPKCS7signature.Update (authAttributeBytes, 0, authAttributeBytes.Length);

            byte[] encodedSignature = pdfPKCS7signature.GetEncodedPKCS7 (hash, timestamp);
            byte[] paddedSignature = new byte[ContentEstimated];
            System.Array.Copy (encodedSignature, 0, paddedSignature, 0, encodedSignature.Length);

            if (ContentEstimated + 2 < encodedSignature.Length)
                throw new Exception ("Not enough space for signature");

            PdfDictionary dict = new PdfDictionary ();
            dict.Put (PdfName.CONTENTS, new PdfString (paddedSignature).SetHexWriting (true));
            signatureAppearance.Close (dict);
        }
        

        public static void Sign (Signature signature, PDFMetadata metadata, string input, string output) {

        if (signature == null)
                throw new NullReferenceException ();

            if (signature.Store == null)
                throw new NullReferenceException ();

            /* Get Store Private Key and Certificate Chain */

            var name = GetPrivateKeyName (signature.Store);

            if (string.IsNullOrEmpty (name))
                throw new InvalidOperationException ("No private key available");

            var privateKey = signature.Store.GetKey (name).Key;
            X509Certificate[] certificateChain = GetCertificateChain (signature.Store, name);

            if (certificateChain == null)
                throw new InvalidOperationException ("No private key available");

            /* Prepare file input/output */

            PdfReader reader = new PdfReader (input, null);
            FileStream outputFile = new FileStream (output, FileMode.Create, FileAccess.Write);
            PdfStamper stamper = PdfStamper.CreateSignature (reader, outputFile, '\0', null, true);
            stamper.MoreInfo = metadata.InfoHashtable;
            stamper.XmpMetadata = metadata.XmpMetadata;

            /* Create Siganture Appearance */

            PdfSignatureAppearance signatureAppearance = CreateSignatureAppearance (stamper, signature);
            signatureAppearance.SetCrypto (null, certificateChain, null, PdfSignatureAppearance.SELF_SIGNED);
            signatureAppearance.CertificationLevel = PdfSignatureAppearance.CERTIFIED_FORM_FILLING_AND_ANNOTATIONS;

            PdfSignature pdfSignature = new PdfSignature (PdfName.ADOBE_PPKLITE, new PdfName ("adbe.pkcs7.detached"));
            pdfSignature.Reason = signatureAppearance.Reason;
            pdfSignature.Location = signatureAppearance.Location;
            pdfSignature.Contact = signatureAppearance.Contact;
            pdfSignature.Date = new PdfDate (signatureAppearance.SignDate);
            signatureAppearance.CryptoDictionary = pdfSignature;

            // Preallocate excluded byte-range for the signature content (hex encoded)

            var excludedByteRange = new Dictionary<PdfName, int> ();
            excludedByteRange[PdfName.CONTENTS] = ContentEstimated * 2 + 2;
            signatureAppearance.PreClose (new Hashtable (excludedByteRange));

            // Get signature hash & certificate chain OCSP

            byte[] hash = CreateMessageDigestHash (signatureAppearance.RangeStream);
            byte[] ocsp = GetCertificateChainOCSP (certificateChain);

            // Sign the document

            PKCS7SignDocument(privateKey, certificateChain, hash, ocsp, signatureAppearance);

        }

        public static SignatureValidation VerifySignature (X509Certificate certificate, string input) {

            PdfReader reader = new PdfReader (input);
            AcroFields af = reader.AcroFields;
            ArrayList names = af.GetSignatureNames ();

            if (names.Count == 0) {
                return null;
            }

            SignatureValidation result = null;

            foreach (string name in names) {

                PdfPKCS7 pk = af.VerifySignature (name);

                if ( certificate.SerialNumber.CompareTo(pk.SigningCertificate.SerialNumber) == 0 ) {

                    byte[] b1 = certificate.GetSignature();
                    byte[] b2 = pk.SigningCertificate.GetSignature();

                    if ( b1.SequenceEqual(b2) ) {
                        result = new SignatureValidation();
                        result.SignatureDate= pk.SignDate;
                        result.SignatureName = pk.SignName;
                        result.Reason = pk.Reason;
                        result.Location = pk.Location;
                        result.SignatureCoversWholeDocument = af.SignatureCoversWholeDocument (name);
                        result.Verified = pk.Verify();
                        result.CertificateValid = true;
                        return result;
                    }
                } 
            }
            return null;
        }
    }
}