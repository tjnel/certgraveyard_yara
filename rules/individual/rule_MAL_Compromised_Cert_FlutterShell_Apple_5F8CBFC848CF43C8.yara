import "pe"

rule MAL_Compromised_Cert_FlutterShell_Apple_5F8CBFC848CF43C8 {
   meta:
      description         = "Detects FlutterShell with compromised cert (Apple)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-23"
      version             = "1.0"

      hash                = "021666417de8b9972c179783fe60d4c4ad2d93224e3a0f16137065c960b1b845"
      malware             = "FlutterShell"
      malware_type        = "Unknown"
      malware_notes       = "More info: https://unit42.paloaltonetworks.com/flutterbridge-new-fluttershell-backdoor/"

      signer              = "Yasar Sever"
      cert_issuer_short   = "Apple"
      cert_issuer         = "Apple Inc."
      cert_serial         = "5f:8c:bf:c8:48:cf:43:c8"
      cert_thumbprint     = "53DEDF0E6DA4010597B6AB66692E3648A58B3222"
      cert_valid_from     = "2025-11-23"
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
         sig.serial == "5f:8c:bf:c8:48:cf:43:c8"
      )
}
