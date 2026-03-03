import "pe"

rule MAL_Compromised_Cert_T_21_Microsoft_330007D38040BEA32E92CD64E400000007D380 {
   meta:
      description         = "Detects T-21 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-26"
      version             = "1.0"

      hash                = "602e708dc5c31cd35f95e1a147d1345135aeead8a021fe2be4cfe65220b9ccd9"
      malware             = "T-21"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Anquesia Gray"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:07:d3:80:40:be:a3:2e:92:cd:64:e4:00:00:00:07:d3:80"
      cert_thumbprint     = "E4815DD5E649E90E7123C3296EC2383C11BF2C0B"
      cert_valid_from     = "2026-02-26"
      cert_valid_to       = "2026-03-01"

      country             = "US"
      state               = "Georgia"
      locality            = "Atlanta"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:07:d3:80:40:be:a3:2e:92:cd:64:e4:00:00:00:07:d3:80"
      )
}
