import "pe"

rule MAL_Compromised_Cert_FakeAITrading_Sectigo_2900D40F4C110EDE6C988E42BCE6D313 {
   meta:
      description         = "Detects FakeAITrading with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-21"
      version             = "1.0"

      hash                = "6fdd71d628a82252c86b0efa1f73f8ee14801630b91da47ba42957e4db92d002"
      malware             = "FakeAITrading"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Handan Beihan Internet Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "29:00:d4:0f:4c:11:0e:de:6c:98:8e:42:bc:e6:d3:13"
      cert_thumbprint     = "5f5e0f510b9eeaabd5e54d8943e412e8537348b3"
      cert_valid_from     = "2026-01-21"
      cert_valid_to       = "2027-01-21"

      country             = "CN"
      state               = "河北省"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "29:00:d4:0f:4c:11:0e:de:6c:98:8e:42:bc:e6:d3:13"
      )
}
