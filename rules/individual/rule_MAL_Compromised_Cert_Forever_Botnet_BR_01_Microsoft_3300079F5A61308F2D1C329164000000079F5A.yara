import "pe"

rule MAL_Compromised_Cert_Forever_Botnet_BR_01_Microsoft_3300079F5A61308F2D1C329164000000079F5A {
   meta:
      description         = "Detects Forever Botnet,BR-01 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-24"
      version             = "1.0"

      hash                = "587fc7679681f1fba3bd4f8eceef60f28bcda87fe178c33b001ac11935028ff8"
      malware             = "Forever Botnet,BR-01"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "STARQUESHA ANDERSON"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:07:9f:5a:61:30:8f:2d:1c:32:91:64:00:00:00:07:9f:5a"
      cert_thumbprint     = "798C860803B836EAF22D9870A9AE05E577C9C284"
      cert_valid_from     = "2026-03-24"
      cert_valid_to       = "2026-03-27"

      country             = "US"
      state               = "California"
      locality            = "SN BERNRDNO"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:07:9f:5a:61:30:8f:2d:1c:32:91:64:00:00:00:07:9f:5a"
      )
}
