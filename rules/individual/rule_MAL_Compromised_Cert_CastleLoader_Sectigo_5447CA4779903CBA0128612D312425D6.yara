import "pe"

rule MAL_Compromised_Cert_CastleLoader_Sectigo_5447CA4779903CBA0128612D312425D6 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-19"
      version             = "1.0"

      hash                = "001a10b946d41f8794c110f97cd46b961fea0c0d50c92efaef1d166adaffe8b8"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: fillenmore[.]com"

      signer              = "Lway Firmware"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "54:47:ca:47:79:90:3c:ba:01:28:61:2d:31:24:25:d6"
      cert_thumbprint     = "684478482130B435E0CE498D740A295DA4E261E2"
      cert_valid_from     = "2026-03-19"
      cert_valid_to       = "2027-06-17"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "54:47:ca:47:79:90:3c:ba:01:28:61:2d:31:24:25:d6"
      )
}
