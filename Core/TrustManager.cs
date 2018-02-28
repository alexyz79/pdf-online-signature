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
using System.IO;
using System.Linq;
using System.Net.Security;
using Microsoft.Extensions.Configuration;
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
using X509Chain = System.Security.Cryptography.X509Certificates.X509Chain;
using PDFOnlineSignature.Core.Trust;

namespace PDFOnlineSignature.Core {
    public static class TrustManager {
        static IConfiguration Configuration = null;
        static string RootPath {
            get {
                return Configuration.GetValue<string> ("TrustManager:Root", "CERT_ROOT");
            }
        }
        static string UserPrivateCertificatesPath {
            get {
                return RootPath + "/UserPrivate/";
            }
        }
        static string ServerPrivateCertificatesPath {
            get {
                return RootPath + "/ServerPrivate/";
            }
        }

        static string AuthorityPrivateCertificatesPath {
            get {
                return RootPath + "/AuthorityPrivate/";
            }
        }

        static string UserPublicCertificatesPath {
            get {
                return RootPath + "/UserPublic/";
            }
        }
        static string ServerPublicCertificatesPath {
            get {
                return RootPath + "/ServerPublic/";
            }
        }

        static string AuthorityPublicCertificatesPath {
            get {
                return RootPath + "/AuthorityPublic/";
            }
        }

        static X509Certificate2 IssuerCertificate { get; set; }
        static public DistinguishedName IssuerDN { get; private set; }

        private static void SetupDirectories () {
            if (!Directory.Exists (UserPrivateCertificatesPath)) {
                Directory.CreateDirectory (UserPrivateCertificatesPath);
            }

            if (!Directory.Exists (ServerPrivateCertificatesPath)) {
                Directory.CreateDirectory (ServerPrivateCertificatesPath);
            }

            if (!Directory.Exists (AuthorityPrivateCertificatesPath)) {
                Directory.CreateDirectory (AuthorityPrivateCertificatesPath);
            }

            if (!Directory.Exists (UserPublicCertificatesPath)) {
                Directory.CreateDirectory (UserPublicCertificatesPath);
            }

            if (!Directory.Exists (ServerPublicCertificatesPath)) {
                Directory.CreateDirectory (ServerPublicCertificatesPath);
            }

            if (!Directory.Exists (AuthorityPublicCertificatesPath)) {
                Directory.CreateDirectory (AuthorityPublicCertificatesPath);
            }
        }

        private static X509Certificate2 SetupRootCertificate () {

            var certPassword = Configuration.GetValue<string> ("TrustManager:Password", "default password");
   
            IssuerDN = new DistinguishedName () {
                CommonName = Configuration.GetValue<string> ("TrustManager:CommonName", "Certificate Authority Root"),
                Organization = Configuration.GetValue<string> ("TrustManager:Org", "Your Organization"),
                OrganizationalUnit = Configuration.GetValue<string> ("TrustManager:OrgUnit", "Your Organizational Unit"),
                Locality = Configuration.GetValue<string> ("TrustManager:Locality", "Your Locality"),
                Country = Configuration.GetValue<string> ("TrustManager:Country", "Your Country"),
                State = Configuration.GetValue<string> ("TrustManager:State", "Your State"),
                Email = Configuration.GetValue<string> ("TrustManager:Email", "Your Email")
            };

            if (!File.Exists (AuthorityPrivateCertificatesPath + "root.pfx")) {

                DateTime now = DateTime.UtcNow.Date;
        
                var defaultYears = Configuration.GetValue<int> ("TrustManager:Years", 50);

                return IssueCertificate (
                    "root",
                    certPassword,
                    IssuerDN,
                    CertificateType.AuthorityCertificate,
                    now,
                    now.AddYears (defaultYears));
            }

            return LoadCertificate (
                "root",
                certPassword,
                CertificateType.AuthorityCertificate,
                StoreFormat.PFX);
        }

        public static void Init (IConfiguration configuration) {

            Configuration = configuration;
            SetupDirectories ();
            IssuerCertificate = SetupRootCertificate ();
        }
        public static X509Certificate2 LoadCertificate (string basename, string password, CertificateType certtype, StoreFormat format) {

            string filename = "";
            string privateOutputPath = null;
            string publicOutputPath = null;

            if (certtype == CertificateType.AuthorityCertificate) {
                privateOutputPath = AuthorityPrivateCertificatesPath;
                publicOutputPath = AuthorityPublicCertificatesPath;
            } else if (certtype == CertificateType.ServerCertificate) {
                privateOutputPath = ServerPrivateCertificatesPath;
                publicOutputPath = ServerPublicCertificatesPath;
            } else {
                privateOutputPath = UserPrivateCertificatesPath;
                publicOutputPath = UserPublicCertificatesPath;
            }

            switch (format) {
                case StoreFormat.CRT:
                    filename = publicOutputPath + basename + ".crt";
                    break;
                case StoreFormat.P12Store:
                    filename = privateOutputPath + basename + ".p12";
                    break;
                case StoreFormat.PFX:
                    filename = privateOutputPath + basename + ".pfx";
                    break;
                default:
                    throw new NotImplementedException ();
            }

            return new X509Certificate2 (filename, password, X509KeyStorageFlags.Exportable);
        }
        public static X509Certificate2 IssueCertificate (
            string basename,
            string password,
            DistinguishedName dn,
            CertificateType certtype,
            DateTime notBefore,
            DateTime notAfter) {

            var certificateGenerator = new X509V3CertificateGenerator ();
            var privateOutputPath = "";
            var publicOutputPath = "";

            /* Prepare output directories  */
            if (certtype == CertificateType.AuthorityCertificate) {
                privateOutputPath = AuthorityPrivateCertificatesPath;
                publicOutputPath = AuthorityPublicCertificatesPath;
            } else if (certtype == CertificateType.ServerCertificate) {
                privateOutputPath = ServerPrivateCertificatesPath;
                publicOutputPath = ServerPublicCertificatesPath;
            } else {
                privateOutputPath = UserPrivateCertificatesPath;
                publicOutputPath = UserPublicCertificatesPath;
            }

            /* Certificate Asymmetric Keys */
            CryptoApiRandomGenerator randomGenerator = new CryptoApiRandomGenerator ();
            SecureRandom random = new SecureRandom (randomGenerator);

            KeyGenerationParameters keyGenerationParameters = new KeyGenerationParameters (random, 2048);
            RsaKeyPairGenerator keyPairGenerator = new RsaKeyPairGenerator ();
            keyPairGenerator.Init (keyGenerationParameters);

            AsymmetricCipherKeyPair subjectKeyPair = keyPairGenerator.GenerateKeyPair ();
            certificateGenerator.SetPublicKey (subjectKeyPair.Public);

            /* Certificate Serial Number */
            BigInteger serialNumber =
                BigIntegers.CreateRandomInRange (
                    BigInteger.One, BigInteger.ValueOf (Int64.MaxValue), random);

            certificateGenerator.SetSerialNumber (serialNumber);

            /* Certificate Date Constrains */
            certificateGenerator.SetNotBefore (notBefore);
            certificateGenerator.SetNotAfter (notAfter);

            /* Certificate Issuer and Subject DN */
            string issuerName = IssuerDN.ToString ();

            if (certtype == CertificateType.AuthorityCertificate) {
                /* A Certification Authority is a self signed certificate */
                issuerName = dn.ToString ();
            }

            certificateGenerator.SetSubjectDN (new X509Name (dn.ToString ()));
            certificateGenerator.SetIssuerDN (new X509Name (issuerName));

            /* Certificate Alternative Names */
            if (dn.AlternativeNames != null && dn.AlternativeNames.Any ()) {
                var subjectAlternativeNamesExtension =
                    new DerSequence (
                        dn.AlternativeNames.Select (name => new GeneralName (GeneralName.DnsName, name))
                        .ToArray<Asn1Encodable> ());

                certificateGenerator.AddExtension (
                    X509Extensions.SubjectAlternativeName.Id, false, subjectAlternativeNamesExtension);
            }

            /* Certificate Keys Usage  */
            var keyUsageFlags = KeyUsage.KeyCertSign | KeyUsage.KeyEncipherment |
                KeyUsage.DataEncipherment | KeyUsage.DigitalSignature;

            if (certtype == CertificateType.AuthorityCertificate || certtype == CertificateType.ServerCertificate) {
                keyUsageFlags |= KeyUsage.CrlSign | KeyUsage.NonRepudiation;
            }

            certificateGenerator.AddExtension (
                X509Extensions.KeyUsage.Id, false, new KeyUsage (keyUsageFlags));

            /* Certificate Extended Key Usages */
            if (certtype != CertificateType.AuthorityCertificate) {

                KeyPurposeID[] extendedUsages = null;

                if (certtype == CertificateType.ServerCertificate) {
                    extendedUsages = new KeyPurposeID[] {
                    KeyPurposeID.IdKPServerAuth,
                    };
                } else {
                    extendedUsages = new KeyPurposeID[] {
                        KeyPurposeID.IdKPClientAuth,
                        KeyPurposeID.IdKPEmailProtection,
                    };
                }

                certificateGenerator.AddExtension (
                    X509Extensions.ExtendedKeyUsage.Id, false, new ExtendedKeyUsage (extendedUsages));
            }

            /* Certificate Authority Key Identifier */
            /* A Certification Authority is a self signed certificate */
            AsymmetricCipherKeyPair issuerKeyPair = subjectKeyPair;;
            if (certtype != CertificateType.AuthorityCertificate) {
                issuerKeyPair = DotNetUtilities.GetKeyPair (IssuerCertificate.PrivateKey);
            }

            var issuerPKIFactory = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo (issuerKeyPair.Public);
            var generalNames = new GeneralNames (
                new GeneralName (new X509Name (issuerName)));

            /* A Certification Authority is a self signed certificate */
            BigInteger issuerSerialNumber = serialNumber;
            if (certtype != CertificateType.AuthorityCertificate) {
                issuerSerialNumber = new BigInteger (IssuerCertificate.GetSerialNumber ());
            }

            var authorityKIExtension =
                new AuthorityKeyIdentifier (
                    issuerPKIFactory, generalNames, issuerSerialNumber);

            certificateGenerator.AddExtension (
                X509Extensions.AuthorityKeyIdentifier.Id, false, authorityKIExtension);

            /* Certificate Subject Key Identifier */
            var subjectPKIFactory = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo (subjectKeyPair.Public);
            var subjectKIExtension = new SubjectKeyIdentifier (subjectPKIFactory);
            certificateGenerator.AddExtension (
                X509Extensions.SubjectKeyIdentifier.Id, false, subjectKIExtension);

            /* Certificate Basic constrains */
            bool isCertificateAuthority = false;
            if (certtype == CertificateType.AuthorityCertificate) {
                isCertificateAuthority = true;
            }

            var basicConstrains = new BasicConstraints (isCertificateAuthority);
            certificateGenerator.AddExtension (
                X509Extensions.BasicConstraints.Id, true, basicConstrains);

            /* Generate BouncyCastle Certificate */
            ISignatureFactory signatureFactory = new Asn1SignatureFactory (
                "SHA512WITHRSA",
                issuerKeyPair.Private,
                random
            );

            /* Generate P12 Certificate Store and write to disk*/
            var store = new Pkcs12Store ();

            var certificate = certificateGenerator.Generate (signatureFactory);
            var certificateEntry = new X509CertificateEntry (certificate);
            var stream = new MemoryStream ();

            store.SetCertificateEntry (dn.ToString (), certificateEntry);
            store.SetKeyEntry (dn.ToString (), new AsymmetricKeyEntry (subjectKeyPair.Private), new [] { certificateEntry });
            store.Save (stream, password.ToCharArray (), random);

            File.WriteAllBytes (privateOutputPath + basename + ".p12", stream.ToArray ());

            /* Convert to Microsoft X509Certificate2 and write to disk pfx and der files */
            var convertedCertificate =
                new X509Certificate2 (stream.ToArray (),
                    password,
                    X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);

            File.WriteAllBytes (privateOutputPath + basename + ".pfx", convertedCertificate.Export (X509ContentType.Pfx, password));
            File.WriteAllBytes (publicOutputPath + basename + ".crt", convertedCertificate.Export (X509ContentType.Cert, password));

            return convertedCertificate;
        }
        public static bool CertificateAvailable (string basename, CertificateType certtype, StoreFormat format) {

            return File.Exists (CertificatePath (basename, certtype, format));
        }

        public static string CertificatePath (string basename, CertificateType certtype, StoreFormat format) {
            string filename = "";
            string privateOutputPath = null;
            string publicOutputPath = null;

            if (certtype == CertificateType.AuthorityCertificate) {
                privateOutputPath = AuthorityPrivateCertificatesPath;
                publicOutputPath = AuthorityPublicCertificatesPath;
            } else if (certtype == CertificateType.ServerCertificate) {
                privateOutputPath = ServerPrivateCertificatesPath;
                publicOutputPath = ServerPublicCertificatesPath;
            } else {
                privateOutputPath = UserPrivateCertificatesPath;
                publicOutputPath = UserPublicCertificatesPath;
            }

            switch (format) {
                case StoreFormat.CRT:
                    filename = publicOutputPath + basename + ".crt";
                    break;
                case StoreFormat.P12Store:
                    filename = privateOutputPath + basename + ".p12";
                    break;
                case StoreFormat.PFX:
                    filename = privateOutputPath + basename + ".pfx";
                    break;
                default:
                    throw new NotImplementedException ();
            }

            return filename;
        }

        internal static Pkcs12Store LoadPkcs12Store (string basename, string password, CertificateType certtype) {
            string privateOutputPath = null;

            if (certtype == CertificateType.AuthorityCertificate) {
                privateOutputPath = AuthorityPrivateCertificatesPath;
            } else if (certtype == CertificateType.ServerCertificate) {
                privateOutputPath = ServerPrivateCertificatesPath;
            } else {
                privateOutputPath = UserPrivateCertificatesPath;
            }

            var store = new Pkcs12Store ();

            using (Stream stream = new FileStream (
                privateOutputPath + basename + ".p12",
                FileMode.Open,
                FileAccess.Read)) {

                try
                {
                    store.Load (stream, password.ToCharArray ());
                }
                catch (System.Exception)
                {
                    store = null;
                }

                stream.Close();

            }

            return store;
        }

        internal static X509Certificate LoadX509Certificate (string basename, CertificateType certtype) {

            X509Certificate2 certificate2 = LoadCertificate (basename, null, certtype, StoreFormat.CRT);
            var parser = new X509CertificateParser ();
            var certificate = parser.ReadCertificate (certificate2.GetRawCertData ());
            return certificate;
        }

        internal static bool ValidateCertificate (X509Certificate2 certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors) {
            return true;
        }
    }
}