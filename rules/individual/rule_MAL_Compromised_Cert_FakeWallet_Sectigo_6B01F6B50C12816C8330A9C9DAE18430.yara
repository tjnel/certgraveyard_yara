import "pe"

rule MAL_Compromised_Cert_FakeWallet_Sectigo_6B01F6B50C12816C8330A9C9DAE18430 {
   meta:
      description         = "Detects FakeWallet with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-21"
      version             = "1.0"

      hash                = "c68dee9f88e1eddbd6bfcd233f8c136becd1c7418ce9ae06ba457fb5cd5061db"
      malware             = "FakeWallet"
      malware_type        = "Unknown"
      malware_notes       = "Malware impersonating Neon Wallet"

      signer              = "Yihua Yiye Education Technology (Wuhan) Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "6b:01:f6:b5:0c:12:81:6c:83:30:a9:c9:da:e1:84:30"
      cert_thumbprint     = "C818E3E01F1DAE965A675B069A84348DFCE5F702"
      cert_valid_from     = "2026-01-21"
      cert_valid_to       = "2027-01-21"

      country             = "CN"
      state               = "Hubei Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91420111MA49E0C72T"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "6b:01:f6:b5:0c:12:81:6c:83:30:a9:c9:da:e1:84:30"
      )
}
