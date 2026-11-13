import "pe"

rule MAL_Compromised_Cert_TamperedChef_GlobalSign_2A9BDB27841077D5B9E63C58 {
   meta:
      description         = "Detects TamperedChef with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-08"
      version             = "1.0"

      hash                = "227a0c8bf9abc7261971daf865b23fdffb4e63dce9018ab1caef58c36aea342e"
      malware             = "TamperedChef"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "UTAH TECHNICAL, LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "2a:9b:db:27:84:10:77:d5:b9:e6:3c:58"
      cert_thumbprint     = "c421630000b4f3001fe831a1f3eb0007e0d69ddb"
      cert_valid_from     = "2026-05-08"
      cert_valid_to       = "2027-05-09"

      country             = "US"
      state               = "Georgia"
      locality            = "Alpharetta"
      email               = "devops@utahtechnologylabs.com"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "2a:9b:db:27:84:10:77:d5:b9:e6:3c:58"
      )
}
