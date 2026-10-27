import "pe"

rule MAL_Compromised_Cert_Cloudhaze_Microsoft_3300030C217D23BC4078CAE8F3000000030C21 {
   meta:
      description         = "Detects Cloudhaze with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-07-10"
      version             = "1.0"

      hash                = "8644bb2ba39ddad352e82cc8fc827986940dec126527ed1cb6fa532e002bea86"
      malware             = "Cloudhaze"
      malware_type        = "Remote access tool"
      malware_notes       = "https://rogueauthority.org/quartzline-signed-pdf-viewer-zenith-backdoor"

      signer              = "ZEPHYR LAWN CARE, LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:03:0c:21:7d:23:bc:40:78:ca:e8:f3:00:00:00:03:0c:21"
      cert_thumbprint     = "59517e26a7a896c68a54d121f04cb156d5860e58"
      cert_valid_from     = "2026-07-10"
      cert_valid_to       = "2026-07-13"

      country             = "US"
      state               = "Florida"
      locality            = "Zephyrhills"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:03:0c:21:7d:23:bc:40:78:ca:e8:f3:00:00:00:03:0c:21"
      )
}
