import "pe"

rule MAL_Compromised_Cert_UpdateLogger_Sectigo_7AF487B9452C297BFA92808051E5BB69 {
   meta:
      description         = "Detects UpdateLogger with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-20"
      version             = "1.0"

      hash                = "5b96280469074f69f4805caddae054c1bdab3dd0735e7f64d79f26f745bccee3"
      malware             = "UpdateLogger"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Progenies d.o.o"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "7a:f4:87:b9:45:2c:29:7b:fa:92:80:80:51:e5:bb:69"
      cert_thumbprint     = "67659bf4f25e3e653b7f3156261773d7d50729ae"
      cert_valid_from     = "2026-08-20"
      cert_valid_to       = "2027-08-20"

      country             = "HR"
      state               = "Grad Zagreb"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "7a:f4:87:b9:45:2c:29:7b:fa:92:80:80:51:e5:bb:69"
      )
}
