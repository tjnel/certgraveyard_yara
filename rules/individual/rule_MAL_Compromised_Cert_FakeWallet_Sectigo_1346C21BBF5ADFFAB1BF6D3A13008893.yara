import "pe"

rule MAL_Compromised_Cert_FakeWallet_Sectigo_1346C21BBF5ADFFAB1BF6D3A13008893 {
   meta:
      description         = "Detects FakeWallet with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-23"
      version             = "1.0"

      hash                = "e66e30257bffaa087c73b91566c75f5333db8b8d787c205028b845e8f9864ca2"
      malware             = "FakeWallet"
      malware_type        = "Unknown"
      malware_notes       = "Fake Nem Wallet"

      signer              = "Avento Software OÜ"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "13:46:c2:1b:bf:5a:df:fa:b1:bf:6d:3a:13:00:88:93"
      cert_thumbprint     = "21c673eb016d7732fee46a1316ac79e52e3e9cda"
      cert_valid_from     = "2026-06-23"
      cert_valid_to       = "2027-06-23"

      country             = "EE"
      state               = "Harjumaa"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "13:46:c2:1b:bf:5a:df:fa:b1:bf:6d:3a:13:00:88:93"
      )
}
