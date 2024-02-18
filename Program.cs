using System.Globalization;
using System.Net.Security;
using System.Net;

static bool isValidSSLCert(string domain, double minValidDays)
{
	bool isValid = false;
	AutoResetEvent autoResetEvent = new AutoResetEvent(false);

	HttpWebRequest request = WebRequest.CreateHttp($"https://{domain}");

	// ServerCertificateValidationCallback
	request.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) =>
	{
		CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;
		var expirationDate = DateTime.Parse(certificate.GetExpirationDateString(), CultureInfo.InvariantCulture);

		if ((expirationDate - DateTime.Today >= TimeSpan.FromDays(minValidDays)) && sslPolicyErrors == SslPolicyErrors.None)
		{
			isValid = true;
		}
		else
		{
			isValid = false;
		}

		autoResetEvent.Set(); // Signal that the callback has completed
		return isValid; // This return statement is ignored by the callback
	};

	using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
	{
		// Wait for the callback to complete
		autoResetEvent.WaitOne();
	}

	return isValid;
}

//Usage
//bool validSSLCert = isValidSSLCert("google.com", 30);
