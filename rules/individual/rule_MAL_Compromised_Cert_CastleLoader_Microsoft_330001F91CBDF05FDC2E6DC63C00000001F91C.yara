import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_330001F91CBDF05FDC2E6DC63C00000001F91C {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-15"
      version             = "1.0"

      hash                = "891e821627a7dc6450cda47c0164fa90f63312484f8e603ed50d8e029b917852"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "OC Agro ApS"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:01:f9:1c:bd:f0:5f:dc:2e:6d:c6:3c:00:00:00:01:f9:1c"
      cert_thumbprint     = "D401EB4B8956E0D2B4B200036A16C764B6EDE463"
      cert_valid_from     = "2026-06-15"
      cert_valid_to       = "2026-06-18"

      country             = "DK"
      state               = "Central Jutland"
      locality            = "Hammel"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:01:f9:1c:bd:f0:5f:dc:2e:6d:c6:3c:00:00:00:01:f9:1c"
      )
}
