import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Sectigo_00DFC63ED833CE7EF89B6F7C00B0D7D663 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-02"
      version             = "1.0"

      hash                = "03ee3e6eb7772877eff5c7d26629a6c79a5b03647ac77d5ade067cbbc27932d4"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Bengbu Yitongjin Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:df:c6:3e:d8:33:ce:7e:f8:9b:6f:7c:00:b0:d7:d6:63"
      cert_thumbprint     = "A64E5668AA1C7B2E90553CE645361E3E39F85729"
      cert_valid_from     = "2025-10-02"
      cert_valid_to       = "2026-10-02"

      country             = "CN"
      state               = "Anhui Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91340303MADCNQT61A"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:df:c6:3e:d8:33:ce:7e:f8:9b:6f:7c:00:b0:d7:d6:63"
      )
}
