import "pe"

rule MAL_Compromised_Cert_ValleyRAT_Certum_666B914A0E24DBE5775B9A69A3FB7CFB {
   meta:
      description         = "Detects ValleyRAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-23"
      version             = "1.0"

      hash                = "f231eb3b69bc197480b26779893f313d12267cb15f052475d0bcd097bd9feb4c"
      malware             = "ValleyRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Wei Liu"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "66:6b:91:4a:0e:24:db:e5:77:5b:9a:69:a3:fb:7c:fb"
      cert_thumbprint     = "f6b2516cbb27722842233bcce8f512542d8d938b"
      cert_valid_from     = "2026-03-23"
      cert_valid_to       = "2027-03-23"

      country             = "CN"
      state               = "辽宁"
      locality            = "庄河"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "66:6b:91:4a:0e:24:db:e5:77:5b:9a:69:a3:fb:7c:fb"
      )
}
