import "pe"

rule MAL_Compromised_Cert_FlutterShell_Apple_36A88C562EDD9237 {
   meta:
      description         = "Detects FlutterShell with compromised cert (Apple)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-31"
      version             = "1.0"

      hash                = "644fc49fa1006a2a2acace694e5fb83753164e2617051ece6d9dc9ea32329e70"
      malware             = "FlutterShell"
      malware_type        = "Unknown"
      malware_notes       = "More info: https://unit42.paloaltonetworks.com/flutterbridge-new-fluttershell-backdoor/"

      signer              = "Batuhan Dabag"
      cert_issuer_short   = "Apple"
      cert_issuer         = "Apple Inc."
      cert_serial         = "36:a8:8c:56:2e:dd:92:37"
      cert_thumbprint     = "4E30A8AB730CCEA71338CE9F3E5027EB94F7D32C"
      cert_valid_from     = "2025-12-31"
      cert_valid_to       = "2027-02-01"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Apple Inc." and
         sig.serial == "36:a8:8c:56:2e:dd:92:37"
      )
}
