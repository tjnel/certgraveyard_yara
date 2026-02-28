import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Sectigo_00D395614C911201F1178CC6EA695C2862 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-29"
      version             = "1.0"

      hash                = "d2859d74989e1dcd447b3c9799b5507aef69e3f7b3a38751b0a2c88ca124432a"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SAKHRI YANIS"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:d3:95:61:4c:91:12:01:f1:17:8c:c6:ea:69:5c:28:62"
      cert_thumbprint     = "89F20890ABE12AB865A399860CAA9B437E9C7C9D"
      cert_valid_from     = "2026-01-29"
      cert_valid_to       = "2027-01-29"

      country             = "FR"
      state               = "Ile-de-France"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "989 260 229"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:d3:95:61:4c:91:12:01:f1:17:8c:c6:ea:69:5c:28:62"
      )
}
