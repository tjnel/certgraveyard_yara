import "pe"

rule MAL_Compromised_Cert_VariantLoader_Microsoft_33000854A07FFD5E99A098C2110000000854A0 {
   meta:
      description         = "Detects VariantLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-18"
      version             = "1.0"

      hash                = "8fa2bfe82742ea8e21d0a889cdbc3444e5e783159d5063f390678d9aed6c72d4"
      malware             = "VariantLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: 188.137.246.189"

      signer              = "Mariah Lingle"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:08:54:a0:7f:fd:5e:99:a0:98:c2:11:00:00:00:08:54:a0"
      cert_thumbprint     = "A9D1DF2A3D6AA2422C7A683B54A9C70B7D0ED702"
      cert_valid_from     = "2026-03-18"
      cert_valid_to       = "2026-03-21"

      country             = "US"
      state               = "Montana"
      locality            = "Columbia Fals"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:08:54:a0:7f:fd:5e:99:a0:98:c2:11:00:00:00:08:54:a0"
      )
}
