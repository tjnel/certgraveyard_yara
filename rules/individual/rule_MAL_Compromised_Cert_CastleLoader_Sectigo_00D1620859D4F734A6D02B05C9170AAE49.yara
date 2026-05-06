import "pe"

rule MAL_Compromised_Cert_CastleLoader_Sectigo_00D1620859D4F734A6D02B05C9170AAE49 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-23"
      version             = "1.0"

      hash                = "e9b84dcb539bb0c1f2a0f73d3de1372ecf8399c970c87d356b77b6f0008bede1"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: goffmanlawyer[.]com"

      signer              = "OU mihameya"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:d1:62:08:59:d4:f7:34:a6:d0:2b:05:c9:17:0a:ae:49"
      cert_thumbprint     = "69B68986FAC94AC12D34E8B247F58E24CD6C17C0"
      cert_valid_from     = "2026-04-23"
      cert_valid_to       = "2027-04-23"

      country             = "EE"
      state               = "Ida-Virumaa"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "17277622"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:d1:62:08:59:d4:f7:34:a6:d0:2b:05:c9:17:0a:ae:49"
      )
}
