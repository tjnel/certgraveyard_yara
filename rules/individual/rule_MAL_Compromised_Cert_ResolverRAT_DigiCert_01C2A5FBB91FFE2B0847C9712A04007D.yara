import "pe"

rule MAL_Compromised_Cert_ResolverRAT_DigiCert_01C2A5FBB91FFE2B0847C9712A04007D {
   meta:
      description         = "Detects ResolverRAT with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-18"
      version             = "1.0"

      hash                = "3b0de26de5b19cef038df70f8c2a002f5809f6b13cfab2a13d8f36631947c1c7"
      malware             = "ResolverRAT"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "51.395.356 CLAUDIVAN DA SILVA DOS SANTOS"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "01:c2:a5:fb:b9:1f:fe:2b:08:47:c9:71:2a:04:00:7d"
      cert_thumbprint     = "BD43E4C607E160A1C5E84FF9CEF01C8C3C5F9575"
      cert_valid_from     = "2026-03-18"
      cert_valid_to       = "2027-03-17"

      country             = "BR"
      state               = "Sao Paulo"
      locality            = "SAO PAULO"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "01:c2:a5:fb:b9:1f:fe:2b:08:47:c9:71:2a:04:00:7d"
      )
}
