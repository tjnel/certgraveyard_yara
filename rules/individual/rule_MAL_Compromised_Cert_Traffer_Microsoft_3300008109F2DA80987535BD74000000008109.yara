import "pe"

rule MAL_Compromised_Cert_Traffer_Microsoft_3300008109F2DA80987535BD74000000008109 {
   meta:
      description         = "Detects Traffer with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-25"
      version             = "1.0"

      hash                = "5007f2d2919401ea0e67933f0c00f09cc56d153f6e93a3fe0fc840b42b2375b8"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Marker Hill Construction Inc"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:00:81:09:f2:da:80:98:75:35:bd:74:00:00:00:00:81:09"
      cert_thumbprint     = "14B09BFB289DAEDB6B1C83F72790AF2C288F4550"
      cert_valid_from     = "2026-04-25"
      cert_valid_to       = "2026-04-28"

      country             = "US"
      state               = "Colorado"
      locality            = "Denver"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:00:81:09:f2:da:80:98:75:35:bd:74:00:00:00:00:81:09"
      )
}
