import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_Sectigo_45D3E97BAEE6E4057EF4FA680CAF010D {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-27"
      version             = "1.0"

      hash                = "82447740e38310f28c47a61c7cb743dfa075d4194bb5588812a08895e02c89ea"
      malware             = "Zhong Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xiamen Sihai Rongchuang Network Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "45:d3:e9:7b:ae:e6:e4:05:7e:f4:fa:68:0c:af:01:0d"
      cert_thumbprint     = "4ECD789457499B7C0080A9CAA5A78FD18FDB618F"
      cert_valid_from     = "2026-01-27"
      cert_valid_to       = "2027-01-27"

      country             = "---"
      state               = "---"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "45:d3:e9:7b:ae:e6:e4:05:7e:f4:fa:68:0c:af:01:0d"
      )
}
