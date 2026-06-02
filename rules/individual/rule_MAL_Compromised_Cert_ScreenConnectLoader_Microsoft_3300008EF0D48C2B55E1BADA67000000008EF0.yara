import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_3300008EF0D48C2B55E1BADA67000000008EF0 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-27"
      version             = "1.0"

      hash                = "d856006daeaa66492b526f7ed0f11c79c06d756b6fbdf3e72161c48a1ed0a7a0"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Palacios Edgar"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:00:8e:f0:d4:8c:2b:55:e1:ba:da:67:00:00:00:00:8e:f0"
      cert_thumbprint     = "A4DBE6906EECA6AEA18C14A226E6B43568776EA5"
      cert_valid_from     = "2026-04-27"
      cert_valid_to       = "2026-04-30"

      country             = "US"
      state               = "Texas"
      locality            = "San Antonio"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:00:8e:f0:d4:8c:2b:55:e1:ba:da:67:00:00:00:00:8e:f0"
      )
}
