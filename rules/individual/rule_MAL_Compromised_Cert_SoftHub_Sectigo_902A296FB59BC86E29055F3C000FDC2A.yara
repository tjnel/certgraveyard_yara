import "pe"

rule MAL_Compromised_Cert_SoftHub_Sectigo_902A296FB59BC86E29055F3C000FDC2A {
   meta:
      description         = "Detects SoftHub with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-11"
      version             = "1.0"

      hash                = "51c99c352c7bda319d463aac691cac885466b83690e4ed589e1ee0886bcd66b6"
      malware             = "SoftHub"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Wijtvliet Agro"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "90:2a:29:6f:b5:9b:c8:6e:29:05:5f:3c:00:0f:dc:2a"
      cert_thumbprint     = "098f4c89da0f0ce1efd8335d13986323caa4098b"
      cert_valid_from     = "2026-08-11"
      cert_valid_to       = "2027-08-11"

      country             = "NL"
      state               = "Noord-Brabant"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "90:2a:29:6f:b5:9b:c8:6e:29:05:5f:3c:00:0f:dc:2a"
      )
}
