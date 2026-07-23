import "pe"

rule MAL_Compromised_Cert_CrocoRAT_Certum_38415A82BCDED4B2A8A4D8394F7EBB55 {
   meta:
      description         = "Detects CrocoRAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-23"
      version             = "1.0"

      hash                = "77e4df8122d4fd0bcb7e04623ed479d2c90841ccaa0c6ad9cfc342f9d622860d"
      malware             = "CrocoRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "1090 Fishing Mapp Oy"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "38:41:5a:82:bc:de:d4:b2:a8:a4:d8:39:4f:7e:bb:55"
      cert_thumbprint     = "ce018a156bcafeaff7740c9bbb93e45788e3a31d"
      cert_valid_from     = "2026-04-23"
      cert_valid_to       = "2027-04-23"

      country             = "FI"
      state               = "Keski-Suomi"
      locality            = "Jyväskylä"
      email               = "---"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "38:41:5a:82:bc:de:d4:b2:a8:a4:d8:39:4f:7e:bb:55"
      )
}
