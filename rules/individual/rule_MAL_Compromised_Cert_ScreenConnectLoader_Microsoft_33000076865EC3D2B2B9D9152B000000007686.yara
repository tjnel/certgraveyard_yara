import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_33000076865EC3D2B2B9D9152B000000007686 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-24"
      version             = "1.0"

      hash                = "93be0f5ed2c41520974374da3533c9146e10f4269fc01cf4d25390449dc54878"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Avery Benavidez"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:00:76:86:5e:c3:d2:b2:b9:d9:15:2b:00:00:00:00:76:86"
      cert_thumbprint     = "B7531714F5AF44F9972F85C50A7D4FDF9162AC99"
      cert_valid_from     = "2026-04-24"
      cert_valid_to       = "2026-04-27"

      country             = "US"
      state               = "Texas"
      locality            = "San Antonio"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:00:76:86:5e:c3:d2:b2:b9:d9:15:2b:00:00:00:00:76:86"
      )
}
