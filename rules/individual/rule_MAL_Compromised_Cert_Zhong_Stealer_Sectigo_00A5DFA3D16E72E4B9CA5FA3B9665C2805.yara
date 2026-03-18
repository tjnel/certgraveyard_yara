import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_Sectigo_00A5DFA3D16E72E4B9CA5FA3B9665C2805 {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-23"
      version             = "1.0"

      hash                = "a8d911dd10c0abac0de077868ab455f1869f63cda456ecab048a1572c8d35e7f"
      malware             = "Zhong Stealer"
      malware_type        = "Infostealer"
      malware_notes       = ""

      signer              = "Xiamen Lede Song Information Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:a5:df:a3:d1:6e:72:e4:b9:ca:5f:a3:b9:66:5c:28:05"
      cert_thumbprint     = "FEC827C25EF8D92D9647E0BC10A5B444C94F2901"
      cert_valid_from     = "2026-01-23"
      cert_valid_to       = "2027-01-23"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91350203302946627U"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:a5:df:a3:d1:6e:72:e4:b9:ca:5f:a3:b9:66:5c:28:05"
      )
}
