import "pe"

rule MAL_Compromised_Cert_FakeWallet_Sectigo_3CBE9D4011670300D1997DB20AD1468E {
   meta:
      description         = "Detects FakeWallet with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-21"
      version             = "1.0"

      hash                = "9eb8fadaf8c766972a690ac705d6a4af32db75d84d290aa8a8584885e59204dd"
      malware             = "FakeWallet"
      malware_type        = "Unknown"
      malware_notes       = "Malicious installer impersonating Sollet Wallet"

      signer              = "Yixing Guhao Ceramics Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "3c:be:9d:40:11:67:03:00:d1:99:7d:b2:0a:d1:46:8e"
      cert_thumbprint     = "15F82BC7DA08A375FBFF15A9E9766A8C34896DA3"
      cert_valid_from     = "2026-01-21"
      cert_valid_to       = "2027-01-21"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "3c:be:9d:40:11:67:03:00:d1:99:7d:b2:0a:d1:46:8e"
      )
}
