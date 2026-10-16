import "pe"

rule MAL_Compromised_Cert_Zalmoxis_Certum_78A86CAAFDD6F6DE0DC5CF2A0C128265 {
   meta:
      description         = "Detects Zalmoxis with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-11"
      version             = "1.0"

      hash                = "25389448ceaa92b3133c26e4fe2cc34cfc908f32cf44d93cc886a2d62deb06e1"
      malware             = "Zalmoxis"
      malware_type        = "Infostealer"
      malware_notes       = "https://rogueauthority.org/signed-crash-handler-name-gate-zalmoxis-stealer"

      signer              = "Teapot Software Oy"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "78:a8:6c:aa:fd:d6:f6:de:0d:c5:cf:2a:0c:12:82:65"
      cert_thumbprint     = "f126870365a648a13d07e907d80bb77173af79cf"
      cert_valid_from     = "2026-08-11"
      cert_valid_to       = "2027-08-11"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "Vantaa"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "78:a8:6c:aa:fd:d6:f6:de:0d:c5:cf:2a:0c:12:82:65"
      )
}
