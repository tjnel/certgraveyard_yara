import "pe"

rule MAL_Compromised_Cert_Certificate_warming_Microsoft_330000CA09BE8AA0DE1BE28F1300000000CA09 {
   meta:
      description         = "Detects Certificate warming with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-07"
      version             = "1.0"

      hash                = "4231e803c2e0189984d0aea505d6f82bb55cc48096b78a7755739a8f4ff14cce"
      malware             = "Certificate warming"
      malware_type        = "Unknown"
      malware_notes       = "This file is being distributed with the certificate to 'warm' the certificate, increasing the certificate's reputation with Microsoft before using it to sign malware."

      signer              = "TERESA ANN BOSWELL"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:00:ca:09:be:8a:a0:de:1b:e2:8f:13:00:00:00:00:ca:09"
      cert_thumbprint     = "119DD81D412363BB088787E7571A0FA7F1E1EE4E"
      cert_valid_from     = "2026-05-07"
      cert_valid_to       = "2026-05-10"

      country             = "US"
      state               = "Arizona"
      locality            = "Mesa"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:00:ca:09:be:8a:a0:de:1b:e2:8f:13:00:00:00:00:ca:09"
      )
}
