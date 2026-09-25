import "pe"

rule MAL_Compromised_Cert_FakeWallet_Sectigo_5382FA015F08A3697822BB087488B3ED {
   meta:
      description         = "Detects FakeWallet with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-24"
      version             = "1.0"

      hash                = "c539aaa7f532ddbc57d153216e9af2ce453ebb53e42587ce9f1163217f6fe7e0"
      malware             = "FakeWallet"
      malware_type        = "Unknown"
      malware_notes       = "Fake Rakuten Wallet"

      signer              = "BEAUTIFUL MINDS AS"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "53:82:fa:01:5f:08:a3:69:78:22:bb:08:74:88:b3:ed"
      cert_thumbprint     = "2cde7d4cb2dca0ee0d63cfd5db28352b942ca730"
      cert_valid_from     = "2026-06-24"
      cert_valid_to       = "2027-06-24"

      country             = "NO"
      state               = "Østfold"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "53:82:fa:01:5f:08:a3:69:78:22:bb:08:74:88:b3:ed"
      )
}
