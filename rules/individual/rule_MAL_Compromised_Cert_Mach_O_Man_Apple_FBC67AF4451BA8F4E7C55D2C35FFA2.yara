import "pe"

rule MAL_Compromised_Cert_Mach_O_Man_Apple_FBC67AF4451BA8F4E7C55D2C35FFA2 {
   meta:
      description         = "Detects Mach-O Man with compromised cert (Apple)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-14"
      version             = "1.0"

      hash                = "5d67f810bea19b9c3489e0981559af4340be39f188460938c7b11fea854ed06e"
      malware             = "Mach-O Man"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Alex Lopez"
      cert_issuer_short   = "Apple"
      cert_issuer         = "Apple Inc."
      cert_serial         = "fb:c6:7a:f4:45:1b:a8:f4:e7:c5:5d:2c:35:ff:a2"
      cert_thumbprint     = "E082EF46583BFDFA3DB1D45173863E2CBB73F72E"
      cert_valid_from     = "2025-11-14"
      cert_valid_to       = "2026-11-14"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Apple Inc." and
         sig.serial == "fb:c6:7a:f4:45:1b:a8:f4:e7:c5:5d:2c:35:ff:a2"
      )
}
