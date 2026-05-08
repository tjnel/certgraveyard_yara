import "pe"

rule MAL_Compromised_Cert_APXLoader_Microsoft_3300005CCB507827A61A7DEDCB000000005CCB {
   meta:
      description         = "Detects APXLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-15"
      version             = "1.0"

      hash                = "6fc1d441c8cc9d3208ea36750f311704a2f4c40ef7bcb29eae2712622b382c8e"
      malware             = "APXLoader"
      malware_type        = "Loader"
      malware_notes       = ""

      signer              = "Vic Thadhani"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:00:5c:cb:50:78:27:a6:1a:7d:ed:cb:00:00:00:00:5c:cb"
      cert_thumbprint     = "C3DC3CAF8E959810A96E12FFD0C9C045080E99FA"
      cert_valid_from     = "2026-04-15"
      cert_valid_to       = "2026-04-18"

      country             = "US"
      state               = "California"
      locality            = "PALO ALTO"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:00:5c:cb:50:78:27:a6:1a:7d:ed:cb:00:00:00:00:5c:cb"
      )
}
