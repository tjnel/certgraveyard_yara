import "pe"

rule MAL_Compromised_Cert_FakeRSSGuard_SSL_com_5387706609BB5AD3F52BCAFE1D73F849 {
   meta:
      description         = "Detects FakeRSSGuard with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-26"
      version             = "1.0"

      hash                = "e16618583b9255c3c03feeaa9da1e7c3ef2291764421c0851ecae398c90a5f17"
      malware             = "FakeRSSGuard"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Chernoria Berry"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "53:87:70:66:09:bb:5a:d3:f5:2b:ca:fe:1d:73:f8:49"
      cert_thumbprint     = "6365dab65cdf37b17b60426fe661ebc5739d08b8"
      cert_valid_from     = "2026-08-26"
      cert_valid_to       = "2027-08-26"

      country             = "US"
      state               = "Georgia"
      locality            = "Covington"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "53:87:70:66:09:bb:5a:d3:f5:2b:ca:fe:1d:73:f8:49"
      )
}
