import "pe"

rule MAL_Compromised_Cert_RdViewer_Certum_6174F87754675B7F8454AABB0728A976 {
   meta:
      description         = "Detects RdViewer with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-11-09"
      version             = "1.0"

      hash                = "d23a2c243743d961741caeb69cd23c42b6f516d081d5f8dfe9e508e467ee3dd7"
      malware             = "RdViewer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "李维"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "61:74:f8:77:54:67:5b:7f:84:54:aa:bb:07:28:a9:76"
      cert_thumbprint     = "aa8589abf626710a31b405a6fff15d07bed5bc21"
      cert_valid_from     = "2026-11-09"
      cert_valid_to       = "2027-11-09"

      country             = "CN"
      state               = "湖南省"
      locality            = "常德市"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "61:74:f8:77:54:67:5b:7f:84:54:aa:bb:07:28:a9:76"
      )
}
