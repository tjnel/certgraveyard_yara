import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330007B3F9A9A4D05C01D4ECA700000007B3F9 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-29"
      version             = "1.0"

      hash                = "58ac75759b796dbefff92b94dbadf46060b5cd7f0e1cc6a25b01c0c734de851c"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = "Fake cryptocurrency wallets builds leading to malicious RMM connections"

      signer              = "Perry Sabrina Ann"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:07:b3:f9:a9:a4:d0:5c:01:d4:ec:a7:00:00:00:07:b3:f9"
      cert_thumbprint     = "7A19F151FB6C1BA25435E4C7B455AA2CA783F181"
      cert_valid_from     = "2026-03-29"
      cert_valid_to       = "2026-04-01"

      country             = "US"
      state               = "Hawaii"
      locality            = "Wailuku"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:07:b3:f9:a9:a4:d0:5c:01:d4:ec:a7:00:00:00:07:b3:f9"
      )
}
