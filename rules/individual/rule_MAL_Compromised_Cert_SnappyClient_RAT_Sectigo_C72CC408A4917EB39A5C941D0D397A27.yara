import "pe"

rule MAL_Compromised_Cert_SnappyClient_RAT_Sectigo_C72CC408A4917EB39A5C941D0D397A27 {
   meta:
      description         = "Detects SnappyClient RAT with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-11"
      version             = "1.0"

      hash                = "3ba215692665513abfffd4e815c5c45f2d41e5dcc4283a2a3b740930c5c417c3"
      malware             = "SnappyClient RAT"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Tobias Weihmann Software Development OU"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "c7:2c:c4:08:a4:91:7e:b3:9a:5c:94:1d:0d:39:7a:27"
      cert_thumbprint     = "e2bbeac060f19bd343536d58e84bdce8993aa934"
      cert_valid_from     = "2026-09-11"
      cert_valid_to       = "2027-09-11"

      country             = "EE"
      state               = "Harjumaa"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "c7:2c:c4:08:a4:91:7e:b3:9a:5c:94:1d:0d:39:7a:27"
      )
}
