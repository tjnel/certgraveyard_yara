import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_3300078B2CFE8B1145EAB178EB000000078B2C {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-21"
      version             = "1.0"

      hash                = "d20c029415e0927e86aba3d2da228697c0d56d58464827dbef364483e6b42a17"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = "Fake cryptocurrency wallets builds leading to malicious RMM connections"

      signer              = "Perry Sabrina Ann"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:07:8b:2c:fe:8b:11:45:ea:b1:78:eb:00:00:00:07:8b:2c"
      cert_thumbprint     = "0EA76E18EFF45C107E2A28F659EF10B57C55D848"
      cert_valid_from     = "2026-03-21"
      cert_valid_to       = "2026-03-24"

      country             = "US"
      state               = "Hawaii"
      locality            = "Wailuku"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:07:8b:2c:fe:8b:11:45:ea:b1:78:eb:00:00:00:07:8b:2c"
      )
}
