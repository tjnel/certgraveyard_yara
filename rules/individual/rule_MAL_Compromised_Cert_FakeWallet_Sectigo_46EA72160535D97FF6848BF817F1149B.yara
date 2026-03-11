import "pe"

rule MAL_Compromised_Cert_FakeWallet_Sectigo_46EA72160535D97FF6848BF817F1149B {
   meta:
      description         = "Detects FakeWallet with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-10"
      version             = "1.0"

      hash                = "87cd3ecb5d482ebe548afbcaea1b55a121d13e5b24cca4459a1fcd53a4559a62"
      malware             = "FakeWallet"
      malware_type        = "Unknown"
      malware_notes       = "Malicious installers impersonating crypto applications such as Binance or GoodCrypto"

      signer              = "Keskus marketing"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "46:ea:72:16:05:35:d9:7f:f6:84:8b:f8:17:f1:14:9b"
      cert_thumbprint     = "78DB889C353CA153F23B7BA89AA9DA129B3F71B0"
      cert_valid_from     = "2025-03-10"
      cert_valid_to       = "2026-03-10"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "46:ea:72:16:05:35:d9:7f:f6:84:8b:f8:17:f1:14:9b"
      )
}
