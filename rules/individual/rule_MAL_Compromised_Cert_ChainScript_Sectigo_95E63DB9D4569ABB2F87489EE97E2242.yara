import "pe"

rule MAL_Compromised_Cert_ChainScript_Sectigo_95E63DB9D4569ABB2F87489EE97E2242 {
   meta:
      description         = "Detects ChainScript with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-10-05"
      version             = "1.0"

      hash                = "7cfc7235f99bc8c7e1b49f12cfc33c1c789084d5d6f49bea40917ffb330a7515"
      malware             = "ChainScript"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Sylabiz Software OU"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "95:e6:3d:b9:d4:56:9a:bb:2f:87:48:9e:e9:7e:22:42"
      cert_thumbprint     = "e82a143b76638b5f16671a55512656f60dd35d5d"
      cert_valid_from     = "2026-10-05"
      cert_valid_to       = "2027-10-05"

      country             = "EE"
      state               = "Harjumaa"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "95:e6:3d:b9:d4:56:9a:bb:2f:87:48:9e:e9:7e:22:42"
      )
}
