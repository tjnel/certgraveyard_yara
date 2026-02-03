import "pe"

rule MAL_Compromised_Cert_FakeWallet_Sectigo_59F0E495A504C6E47F40A02BF0BA6DDB {
   meta:
      description         = "Detects FakeWallet with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-09"
      version             = "1.0"

      hash                = "6651210296c02f468f0fecdadcaa06824f9222f0bfd794b78653ff298a84ad34"
      malware             = "FakeWallet"
      malware_type        = "Infostealer"
      malware_notes       = "Application is a fake Multibit wallet installer."

      signer              = "Anhui Shanxian Tongxin Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "59:f0:e4:95:a5:04:c6:e4:7f:40:a0:2b:f0:ba:6d:db"
      cert_thumbprint     = "6394219837078FE26499EAB084B99904626083DD"
      cert_valid_from     = "2026-01-09"
      cert_valid_to       = "2027-01-09"

      country             = "CN"
      state               = "Anhui Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91340104MA8N19889Y"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "59:f0:e4:95:a5:04:c6:e4:7f:40:a0:2b:f0:ba:6d:db"
      )
}
