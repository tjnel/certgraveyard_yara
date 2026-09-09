import "pe"

rule MAL_Compromised_Cert_Wailsloader_Certum_106DB41DF2381F3858ACD9809B904F02 {
   meta:
      description         = "Detects Wailsloader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-21"
      version             = "1.0"

      hash                = "a66c01c55a294a773c5a98b9f286b6ad32055668eb9fe8d77f1f0f55f1a481b1"
      malware             = "Wailsloader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Darko Parun"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "10:6d:b4:1d:f2:38:1f:38:58:ac:d9:80:9b:90:4f:02"
      cert_thumbprint     = "B2E8FF7E86B892826A64D0AD067B6FE42CF66A58"
      cert_valid_from     = "2026-08-21"
      cert_valid_to       = "2027-08-21"

      country             = "HR"
      state               = "Grad Zagreb"
      locality            = "Zagreb"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "10:6d:b4:1d:f2:38:1f:38:58:ac:d9:80:9b:90:4f:02"
      )
}
