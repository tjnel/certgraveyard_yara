import "pe"

rule MAL_Compromised_Cert_SideWinder_Microsoft_330007865479C3D892B4E4EDA7000000078654 {
   meta:
      description         = "Detects SideWinder with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-10-03"
      version             = "1.0"

      hash                = "50d674ab3d7f1fd98e436cf7d324ddb79ab0386911d1c47b3323190bf4d3a54e"
      malware             = "SideWinder"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Ashley Marie Boynton"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:07:86:54:79:c3:d8:92:b4:e4:ed:a7:00:00:00:07:86:54"
      cert_thumbprint     = "9fb89c4839282183e21f3adae0a405193ac0aaea"
      cert_valid_from     = "2026-10-03"
      cert_valid_to       = "2026-10-06"

      country             = "US"
      state               = "nv"
      locality            = "SPARKS"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:07:86:54:79:c3:d8:92:b4:e4:ed:a7:00:00:00:07:86:54"
      )
}
