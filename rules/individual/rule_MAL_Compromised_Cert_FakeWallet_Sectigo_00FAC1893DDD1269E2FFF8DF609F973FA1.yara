import "pe"

rule MAL_Compromised_Cert_FakeWallet_Sectigo_00FAC1893DDD1269E2FFF8DF609F973FA1 {
   meta:
      description         = "Detects FakeWallet with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-20"
      version             = "1.0"

      hash                = "dd346703480c4e0204a647b0f56dec31bd3bb180d858dcbda8b962104c653b3b"
      malware             = "FakeWallet"
      malware_type        = "Unknown"
      malware_notes       = "MAlicious installer impersonating Anchor Wallet"

      signer              = "Wuxi Junhang Metal Materials Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:fa:c1:89:3d:dd:12:69:e2:ff:f8:df:60:9f:97:3f:a1"
      cert_thumbprint     = "AA0AA1375A96591AF74F772E606EFF2E1757EFD1"
      cert_valid_from     = "2026-01-20"
      cert_valid_to       = "2027-01-20"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:fa:c1:89:3d:dd:12:69:e2:ff:f8:df:60:9f:97:3f:a1"
      )
}
