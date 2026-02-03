import "pe"

rule MAL_Compromised_Cert_OpenMyManual_Sectigo_7D06C48CCB0E09945CE6557C7C8EB5A8 {
   meta:
      description         = "Detects OpenMyManual with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-17"
      version             = "1.0"

      hash                = "a16cbf9ab535d4ad628b583ec3e026799f38bb50b98c495333302f7b804390ea"
      malware             = "OpenMyManual"
      malware_type        = "Trojan"
      malware_notes       = "A trojan manual finding application."

      signer              = "Pixel Catalyst Media LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "7d:06:c4:8c:cb:0e:09:94:5c:e6:55:7c:7c:8e:b5:a8"
      cert_thumbprint     = "2D4129109DBF921DB0BC48D41DA32DA0FF1BF024"
      cert_valid_from     = "2025-01-17"
      cert_valid_to       = "2028-01-17"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "7d:06:c4:8c:cb:0e:09:94:5c:e6:55:7c:7c:8e:b5:a8"
      )
}
