import "pe"

rule MAL_Compromised_Cert_Traffer_GlobalSign_393C3D01271DBF2133DBBA98 {
   meta:
      description         = "Detects Traffer with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-31"
      version             = "1.0"

      hash                = "e98d8cd621d4a335d42b887be93e872903eebd59ace03d92965058b5f2bec336"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "REDPOINT SOFTWARE ANS"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "39:3c:3d:01:27:1d:bf:21:33:db:ba:98"
      cert_thumbprint     = "E73C40CEDCE369E9231A2B499AA3B4B513D6C866"
      cert_valid_from     = "2026-03-31"
      cert_valid_to       = "2027-04-01"

      country             = "NO"
      state               = "Trondheim"
      locality            = "Trondheim"
      email               = "steinar@redpoint.as"
      rdn_serial_number   = "989 538 020"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "39:3c:3d:01:27:1d:bf:21:33:db:ba:98"
      )
}
