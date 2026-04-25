import "pe"

rule MAL_Compromised_Cert_OysterLoader_Microsoft_3300049B30C093ECFBF658940B000000049B30 {
   meta:
      description         = "Detects OysterLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-02"
      version             = "1.0"

      hash                = "464db7461d6d67d99132eeaa9962d3691a3efc73f194fb660b4b8c77c10d9591"
      malware             = "OysterLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Nitta-Lai Investment Corp."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:04:9b:30:c0:93:ec:fb:f6:58:94:0b:00:00:00:04:9b:30"
      cert_thumbprint     = "220BF4DB83683AD2B0C78852BE2B1D71699C6AD2"
      cert_valid_from     = "2025-10-02"
      cert_valid_to       = "2025-10-05"

      country             = "CA"
      state               = "Ontario"
      locality            = "Etobicoke"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:04:9b:30:c0:93:ec:fb:f6:58:94:0b:00:00:00:04:9b:30"
      )
}
