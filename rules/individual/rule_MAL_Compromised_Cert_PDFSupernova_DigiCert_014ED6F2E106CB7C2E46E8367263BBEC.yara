import "pe"

rule MAL_Compromised_Cert_PDFSupernova_DigiCert_014ED6F2E106CB7C2E46E8367263BBEC {
   meta:
      description         = "Detects PDFSupernova with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-02"
      version             = "1.0"

      hash                = "438bffa2420a6a0a17344135160c635d16c029d267d441de539fd45f5c17f551"
      malware             = "PDFSupernova"
      malware_type        = "Browser Hijacker"
      malware_notes       = "This fake PDF editor hijacks the user's browser, see more documentation here: https://blog.lukeacha.com/2025/11/fake-pdf-converter-hides-dark-secret.html"

      signer              = "Trivolead LTD"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "01:4e:d6:f2:e1:06:cb:7c:2e:46:e8:36:72:63:bb:ec"
      cert_thumbprint     = "AF1624BC79C60D898374A53D515CB72F558B7420"
      cert_valid_from     = "2025-06-02"
      cert_valid_to       = "2028-06-01"

      country             = "IL"
      state               = "???"
      locality            = "Tel Aviv-Yafo"
      email               = "???"
      rdn_serial_number   = "517161592"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "01:4e:d6:f2:e1:06:cb:7c:2e:46:e8:36:72:63:bb:ec"
      )
}
