import "pe"

rule MAL_Compromised_Cert_LoremIpsumLoader_Microsoft_330007BADC8C3111FCC016B22B00000007BADC {
   meta:
      description         = "Detects LoremIpsumLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-30"
      version             = "1.0"

      hash                = "bd23dea9295ebf3783b8c958723800308f6a77c3e059319af0b9ce0b2f67cb2a"
      malware             = "LoremIpsumLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "Installs a Microsoft Teams as a decoy."

      signer              = "ZINEB SEFRIOUI"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:07:ba:dc:8c:31:11:fc:c0:16:b2:2b:00:00:00:07:ba:dc"
      cert_thumbprint     = "E5F72590511CDFB533E50115EEB0BE8A730D8C56"
      cert_valid_from     = "2026-03-30"
      cert_valid_to       = "2026-04-02"

      country             = "US"
      state               = "California"
      locality            = "HOLLYWOOD"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:07:ba:dc:8c:31:11:fc:c0:16:b2:2b:00:00:00:07:ba:dc"
      )
}
