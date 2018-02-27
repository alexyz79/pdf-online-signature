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
using System.Net;
using System.Net.Mail;
using System.Collections.Generic;
using FluentEmail.Core;
using FluentEmail.Smtp;
using FluentEmail.Razor;
using FluentEmail.Core.Models;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Attachment = FluentEmail.Core.Models.Attachment;

namespace PDFOnlineSignature.Core
{
    public static class EmailManager
    {
        public static string Server { 
            get {
                return Configuration.GetValue<string>("EmailManager:Server",null);;
            } 
        }
        public static string Username { 
            get {
                return Configuration.GetValue<string>("EmailManager:Username",null);;
            } 
        }

        internal static string Password { 
            get {
                return Configuration.GetValue<string>("EmailManager:Password",null);;
            } 
        }
        public static bool EnableSSL { 
            get {
                return Configuration.GetValue<bool>("EmailManager:EnableSSL",false);;
            } 
        }
        public static int Port { 
            get {
                return Configuration.GetValue<int>("EmailManager:Port",23);;
            } 
        }

        public static bool UserCredentials {
            get {
                return Configuration.GetValue<bool>("EmailManager:UseCredentials",false);;
            } 
        }
        public static string Sender { 
            get { 
                return Configuration.GetValue<string>("EmailManager:Sender","sender@domain.com");
            } 
        }
        
        private static IConfiguration Configuration { get; set; }

        public static void Init ( IConfiguration configuration ) {
            Configuration = configuration;
        }

        public async static Task<Attachment> LoadAttachment(string path, string name, string mimetype) {
         
            var memory = new MemoryStream ();

            using (var stream = new FileStream (path, FileMode.Open)) {
                await stream.CopyToAsync (memory);
            }

            memory.Position = 0;

            var result = new Attachment();
            result.Data = memory;
            result.Filename = name;
            result.ContentType = mimetype;
            return result;
        }

        public async static Task<SendResponse> SendEmailHTML(string message, string from, string to, string subject, IList<Attachment> attachments ) {

                SmtpClient client = new SmtpClient (Server);
                client.UseDefaultCredentials = UserCredentials;
                client.Credentials = new NetworkCredential (Username,Password);
                client.Port = Port;
                client.EnableSsl = EnableSSL
                ;
                Email.DefaultSender = new SmtpSender (client);

                var email = Email
                    .From (from)
                    .To (to)
                    .Subject (subject)
                    .UsingTemplate (message, new { });

                if ( attachments != null )
                    email.Attach(attachments);

                return await email.SendAsync ();
        }   

        public async static Task<SendResponse> SendEmail(string message, string from, string to, string subject, IList<Attachment> attachments ) {

                SmtpClient client = new SmtpClient (Server);
                client.UseDefaultCredentials = UserCredentials;
                client.Credentials = new NetworkCredential (Username,Password);
                client.Port = 587;
                client.EnableSsl = true;
                Email.DefaultSender = new SmtpSender (client);

                var email = Email
                    .From (from)
                    .To (to)
                    .Subject (subject)
                    .Body (message);

                if ( attachments != null )
                    email.Attach(attachments);

                return await email.SendAsync ();
        }   
    }
}