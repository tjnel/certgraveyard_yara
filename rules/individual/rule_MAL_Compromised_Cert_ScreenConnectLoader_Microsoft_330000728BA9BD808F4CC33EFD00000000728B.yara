import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330000728BA9BD808F4CC33EFD00000000728B {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-23"
      version             = "1.0"

      hash                = "4717927ba7136c7149215bda25513aacdecef883242a98d2574ea385d4112c02"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Blanchard Nivell"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:00:72:8b:a9:bd:80:8f:4c:c3:3e:fd:00:00:00:00:72:8b"
      cert_thumbprint     = "4C7E351C0606D2AECF5E008FA694E9AFCA9FC026"
      cert_valid_from     = "2026-04-23"
      cert_valid_to       = "2026-04-26"

      country             = "US"
      state               = "Texas"
      locality            = "SAN ANTONIO"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:00:72:8b:a9:bd:80:8f:4c:c3:3e:fd:00:00:00:00:72:8b"
      )
}
