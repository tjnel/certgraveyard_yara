import "pe"

rule MAL_Compromised_Cert_Remcos_RAT_Microsoft_33000026767F84C965E42A1136000000002676 {
   meta:
      description         = "Detects Remcos RAT with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-16"
      version             = "1.0"

      hash                = "7ca636f58225affda4c2e23a3476ebc0a557cfb2ffe50383003a9a13d87fb0fb"
      malware             = "Remcos RAT"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "ENGINEERING AND TECHNICAL PROCUREMENT SERVICES LTD"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:00:26:76:7f:84:c9:65:e4:2a:11:36:00:00:00:00:26:76"
      cert_thumbprint     = "98866FDAB6D2BBCD5D87311AA669EBDD309787AA"
      cert_valid_from     = "2026-04-16"
      cert_valid_to       = "2026-04-19"

      country             = "GB"
      state               = "Essex"
      locality            = "Hadleigh"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:00:26:76:7f:84:c9:65:e4:2a:11:36:00:00:00:00:26:76"
      )
}
