import "pe"

rule MAL_Compromised_Cert_FlutterShell_Apple_226070572ABFE05A {
   meta:
      description         = "Detects FlutterShell with compromised cert (Apple)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-24"
      version             = "1.0"

      hash                = "2dce7accd37a372b73fff5f8764a1c2c046c0db0a33ea9b24cc4a419a2f4d379"
      malware             = "FlutterShell"
      malware_type        = "Unknown"
      malware_notes       = "More info: https://unit42.paloaltonetworks.com/flutterbridge-new-fluttershell-backdoor/"

      signer              = "Yusuf Bal"
      cert_issuer_short   = "Apple"
      cert_issuer         = "Apple Inc."
      cert_serial         = "22:60:70:57:2a:bf:e0:5a"
      cert_thumbprint     = "89F3030F522297D3BC0472594AD593677B205EFC"
      cert_valid_from     = "2026-01-24"
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
         sig.serial == "22:60:70:57:2a:bf:e0:5a"
      )
}
