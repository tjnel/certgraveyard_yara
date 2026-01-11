import "pe"

rule MAL_Compromised_Cert_ValleyRAT_Certum_134216E462B8FC279A7AF7382F45F3D3 {
   meta:
      description         = "Detects ValleyRAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-25"
      version             = "1.0"

      hash                = "f8d5e36ae7af535acd72982e1b5f745adb2b39b83d522709c4c18630bdc87d1c"
      malware             = "ValleyRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "An open source RAT heavily used by Golden Eye Dog. Reaches out to pull down payload: https[:]//microsoft001[.]oss-cn-hangzhou.aliyuncs[.]com/Microsoft/shellcode_encrypted.bin"

      signer              = "Jin Chen"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "13:42:16:e4:62:b8:fc:27:9a:7a:f7:38:2f:45:f3:d3"
      cert_thumbprint     = "2DE84F17D23598E144E8D3033B0E77FE0A197B63"
      cert_valid_from     = "2025-07-25"
      cert_valid_to       = "2026-07-25"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Heyuan"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "13:42:16:e4:62:b8:fc:27:9a:7a:f7:38:2f:45:f3:d3"
      )
}
