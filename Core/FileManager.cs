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
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using PDFOnlineSignature.Models;

namespace PDFOnlineSignature.Core {
    public static class FileManager {
        static IConfiguration Configuration { get; set; }

        public static string DocumentRoot {
            get {
                return Configuration.GetValue<string> ("FileManager:DocumentRoot", "DOCUMENT_ROOT");
            }
        }

        public static void Init (IConfiguration configuration) {
            Configuration = configuration;

            if (!Directory.Exists (DocumentRoot))
                Directory.CreateDirectory (DocumentRoot);
        }

        public async static Task<Document> StoreFile (IFormFile file) {

            Document document = new Document ();
            document.Uuid = Guid.NewGuid ().ToString ();
            document.Name = file.FileName;
            document.Size = file.Length;
            document.CreationdDate = DateTime.UtcNow;
            document.MimeType = "application/pdf";

            using (var stream = new FileStream (DocumentRoot + "/" + document.Uuid, FileMode.Create)) {
                await file.CopyToAsync (stream);
            }

            return document;
        }

        public static async Task<MemoryStream> GetFile (Document document) {

            var path = DocumentRoot + "/" + document.Uuid;

            if (document.Signed == true) {
                path += "-signed";
            }

            var memory = new MemoryStream ();

            using (var stream = new FileStream (path, FileMode.Open)) {
                await stream.CopyToAsync (memory);
            }

            memory.Position = 0;

            return memory;
        }
    }
}