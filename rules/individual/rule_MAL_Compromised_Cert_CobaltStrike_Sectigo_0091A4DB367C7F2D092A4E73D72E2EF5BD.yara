import "pe"

rule MAL_Compromised_Cert_CobaltStrike_Sectigo_0091A4DB367C7F2D092A4E73D72E2EF5BD {
   meta:
      description         = "Detects CobaltStrike with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-02"
      version             = "1.0"

      hash                = "1d3bcced2467d17e2be347629e1aae5ad919c0cf850932eef0fff74fc3ea0f03"
      malware             = "CobaltStrike"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Meltytech, LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV E36"
      cert_serial         = "00:91:a4:db:36:7c:7f:2d:09:2a:4e:73:d7:2e:2e:f5:bd"
      cert_thumbprint     = "E3719FB371B963973CF43F856B7ED18D54CF8563"
      cert_valid_from     = "2026-06-02"
      cert_valid_to       = "2027-06-02"

      country             = "US"
      state               = "California"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "201112310175"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV E36" and
         sig.serial == "00:91:a4:db:36:7c:7f:2d:09:2a:4e:73:d7:2e:2e:f5:bd"
      )
}
