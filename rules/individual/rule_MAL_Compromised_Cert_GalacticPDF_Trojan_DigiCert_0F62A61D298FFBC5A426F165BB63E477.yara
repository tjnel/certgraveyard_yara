import "pe"

rule MAL_Compromised_Cert_GalacticPDF_Trojan_DigiCert_0F62A61D298FFBC5A426F165BB63E477 {
   meta:
      description         = "Detects GalacticPDF, Trojan with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-13"
      version             = "1.0"

      hash                = "4b41fa4a8f00d2e564cb2f9d8ec000f13661ea8bf8036b88b362cf8a2802e513"
      malware             = "GalacticPDF, Trojan"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "MONKEY DIGITAL LTD"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0f:62:a6:1d:29:8f:fb:c5:a4:26:f1:65:bb:63:e4:77"
      cert_thumbprint     = "E356D919C331C0984180CC29224BC5D1E18C9A5D"
      cert_valid_from     = "2026-01-13"
      cert_valid_to       = "2028-01-12"

      country             = "IL"
      state               = "???"
      locality            = "Holon"
      email               = "???"
      rdn_serial_number   = "516195021"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0f:62:a6:1d:29:8f:fb:c5:a4:26:f1:65:bb:63:e4:77"
      )
}
