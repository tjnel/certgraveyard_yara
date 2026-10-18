import "pe"

rule MAL_Compromised_Cert_ManageEngineLoader_Certum_2379CCA1DCB22080C62EB8B6F292C94 {
   meta:
      description         = "Detects ManageEngineLoader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-23"
      version             = "1.0"

      hash                = "bb83d6ffd315a11b24bcb8b65ee946e30f0a64748d30248db25eeda6e17e3d2a"
      malware             = "ManageEngineLoader"
      malware_type        = "Remote access tool"
      malware_notes       = "Deploys ManageEngine Remote Management tool. Targeting Chinese users."

      signer              = "Shuai Zhang"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "23:79:cc:a1:dc:b2:20:80:c6:2e:b8:b6:f2:92:c9:4"
      cert_thumbprint     = "1a55d1ccd1f64f56262b865491b4b4083d1ab95f"
      cert_valid_from     = "2026-03-23"
      cert_valid_to       = "2027-03-23"

      country             = "CN"
      state               = "Hebei"
      locality            = "Hengshui"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "23:79:cc:a1:dc:b2:20:80:c6:2e:b8:b6:f2:92:c9:4"
      )
}
