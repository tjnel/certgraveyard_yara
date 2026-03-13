import "pe"

rule MAL_Compromised_Cert_DonutLoader_GlobalSign_5949C884647BA999C2AC2F78 {
   meta:
      description         = "Detects DonutLoader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-20"
      version             = "1.0"

      hash                = "89e52fa31535e46b5f08becbe1c591aff709036554856e6d250a503719081705"
      malware             = "DonutLoader"
      malware_type        = "Loader"
      malware_notes       = "Decrypts payload using AES encryption, loads AsyncRAT."

      signer              = "成都美付通宝网络科技有限公司"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "59:49:c8:84:64:7b:a9:99:c2:ac:2f:78"
      cert_thumbprint     = "8AD4ACC8DA628F5D09C044FA770105CC151D2989"
      cert_valid_from     = "2026-01-20"
      cert_valid_to       = "2027-01-21"

      country             = "---"
      state               = "---"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "59:49:c8:84:64:7b:a9:99:c2:ac:2f:78"
      )
}
