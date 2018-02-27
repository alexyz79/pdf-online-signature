/*
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
using iTextSharp.text;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.crypto;
using iTextSharp.text.xml.xmp;

namespace PDFOnlineSignature.Core.Trust.Signature
{
    public class PDFMetadata
    {
		public Dictionary<string, string> Info { get; set; }

		public string Author
		{
			get
			{
				if (!Info.ContainsKey("Author")) return String.Empty;

				return Info["Author"];
			}
			set { Info.Add("Author", value); }
		}
		public string Title
		{
			get
			{
				if (!Info.ContainsKey("Title")) return String.Empty;

				return Info["Title"];
			}
			set { Info.Add("Title", value); }
		}
		public string Subject
		{
			get
			{
				if (!Info.ContainsKey("Subject")) return String.Empty;
				return Info["Subject"];
			}
			set { Info.Add("Subject", value); }
		}
		public string Keywords
		{
			get
			{
				if (!Info.ContainsKey("Keywords")) return String.Empty;

				return Info["Keywords"];
			}
			set { Info.Add("Keywords", value); }
		}
		public string Producer
		{
			get
			{
				if (!Info.ContainsKey("Producer")) return String.Empty;
				return Info["Producer"];
			}
			set { Info.Add("Producer", value); }
		}

		public string Creator
		{
			get
			{
				if (!Info.ContainsKey("Creator")) return String.Empty;

				return Info["Creator"];
			}
			set { Info.Add("Creator", value); }
		}

		public Hashtable InfoHashtable {
			get {
				return new Hashtable(Info);
			}
		}

		public byte[] XmpMetadata {
			get {
				MemoryStream os = new System.IO.MemoryStream ();
				XmpWriter xmp = new XmpWriter (os, InfoHashtable);
				byte[] result  = os.ToArray ();
				xmp.Close ();
				return result;
			}
		}

		public PDFMetadata() {
			this.Info = new Dictionary<string, string>();
		}
    }
}