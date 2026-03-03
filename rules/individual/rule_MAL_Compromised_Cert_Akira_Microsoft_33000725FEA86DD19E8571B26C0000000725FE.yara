import "pe"

rule MAL_Compromised_Cert_Akira_Microsoft_33000725FEA86DD19E8571B26C0000000725FE {
   meta:
      description         = "Detects Akira with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-28"
      version             = "1.0"

      hash                = "a8c380b57cb7c381ca6ba845bd7af7333f52ee4dc4e935e98b48bb81facad72b"
      malware             = "Akira"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Donald Gay"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:07:25:fe:a8:6d:d1:9e:85:71:b2:6c:00:00:00:07:25:fe"
      cert_thumbprint     = "9DCB994EA2B8E6169B76A524FAE7B2D2DCD1807D"
      cert_valid_from     = "2026-02-28"
      cert_valid_to       = "2026-03-03"

      country             = "US"
      state               = "Maryland"
      locality            = "Clinton"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:07:25:fe:a8:6d:d1:9e:85:71:b2:6c:00:00:00:07:25:fe"
      )
}
