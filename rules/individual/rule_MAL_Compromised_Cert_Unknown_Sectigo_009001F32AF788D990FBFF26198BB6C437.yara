import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_009001F32AF788D990FBFF26198BB6C437 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-22"
      version             = "1.0"

      hash                = "1fa5315e42dc019667c2d77b96e4f369261f834b9c464435c49cff3c4e7bdf72"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "C&P Global Investors LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:90:01:f3:2a:f7:88:d9:90:fb:ff:26:19:8b:b6:c4:37"
      cert_thumbprint     = "0AA55D396490CC2DE9D27EF33AF10771170DCB91"
      cert_valid_from     = "2026-09-22"
      cert_valid_to       = "2027-10-26"

      country             = "US"
      state               = "California"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:90:01:f3:2a:f7:88:d9:90:fb:ff:26:19:8b:b6:c4:37"
      )
}
