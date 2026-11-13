import "pe"

rule MAL_Compromised_Cert_TamperedChef_GlobalSign_50BC6F42A2B37812B1273009 {
   meta:
      description         = "Detects TamperedChef with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-16"
      version             = "1.0"

      hash                = "b73fe3ba92396c2a051619b13b55e8e8f67b0a6b28b9888ced976047e50f5d9e"
      malware             = "TamperedChef"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Launch Window, LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "50:bc:6f:42:a2:b3:78:12:b1:27:30:09"
      cert_thumbprint     = "3bef796b3c1d09768f1525e7163d8705ecf21e2f"
      cert_valid_from     = "2026-02-16"
      cert_valid_to       = "2027-02-17"

      country             = "US"
      state               = "North Carolina"
      locality            = "Raleigh"
      email               = "adam@launchwindowtech.com"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "50:bc:6f:42:a2:b3:78:12:b1:27:30:09"
      )
}
