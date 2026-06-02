import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330000F3FF728495423D777C0600000000F3FF {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-10"
      version             = "1.0"

      hash                = "f9f0d0f11592a03814f1df78e799244ea4231804fb9968484bcb79ad12eec611"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Palacios Edgar"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:00:f3:ff:72:84:95:42:3d:77:7c:06:00:00:00:00:f3:ff"
      cert_thumbprint     = "2789FCCDA8E27E1ED353DFAFA9F5037AD41C5A58"
      cert_valid_from     = "2026-05-10"
      cert_valid_to       = "2026-05-13"

      country             = "US"
      state               = "Texas"
      locality            = "San Antonio"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:00:f3:ff:72:84:95:42:3d:77:7c:06:00:00:00:00:f3:ff"
      )
}
