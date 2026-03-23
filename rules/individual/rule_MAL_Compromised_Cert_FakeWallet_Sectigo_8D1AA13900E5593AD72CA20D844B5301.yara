import "pe"

rule MAL_Compromised_Cert_FakeWallet_Sectigo_8D1AA13900E5593AD72CA20D844B5301 {
   meta:
      description         = "Detects FakeWallet with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-27"
      version             = "1.0"

      hash                = "1331cbb902615e69ecca45f5c66a06f337af2cd6ac02eeced012dfb5c67ef2aa"
      malware             = "FakeWallet"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Gaomi Degao Machinery Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "8d:1a:a1:39:00:e5:59:3a:d7:2c:a2:0d:84:4b:53:01"
      cert_thumbprint     = ""
      cert_valid_from     = "2026-01-27"
      cert_valid_to       = "2027-01-07"

      country             = "CN"
      state               = "Shandong Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91370785MA3TA0Q097"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "8d:1a:a1:39:00:e5:59:3a:d7:2c:a2:0d:84:4b:53:01"
      )
}
