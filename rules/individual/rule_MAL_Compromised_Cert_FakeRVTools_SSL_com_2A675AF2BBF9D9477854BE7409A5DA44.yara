import "pe"

rule MAL_Compromised_Cert_FakeRVTools_SSL_com_2A675AF2BBF9D9477854BE7409A5DA44 {
   meta:
      description         = "Detects FakeRVTools with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-16"
      version             = "1.0"

      hash                = "b25a752117a9f7072929b88771a281fc7a412a2955b087ef6b3741e8a2434343"
      malware             = "FakeRVTools"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Demarcus Terrell Alexander"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "2a:67:5a:f2:bb:f9:d9:47:78:54:be:74:09:a5:da:44"
      cert_thumbprint     = "4fde8da58c639e77000df6f7f1fada3061cf0a71"
      cert_valid_from     = "2026-08-16"
      cert_valid_to       = "2027-08-16"

      country             = "US"
      state               = "Georgia"
      locality            = "Rome"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "2a:67:5a:f2:bb:f9:d9:47:78:54:be:74:09:a5:da:44"
      )
}
