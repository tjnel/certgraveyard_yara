import "pe"

rule MAL_Compromised_Cert_FakeDocument_GlobalSign_354AE1381C0C0D64FB813198 {
   meta:
      description         = "Detects FakeDocument with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-18"
      version             = "1.0"

      hash                = "728618559f4bda155c1455872b04c940f51c06ca27f1ec8584a431ee4b86e8ed"
      malware             = "FakeDocument"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "EzDistract MicroLeague Network Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "35:4a:e1:38:1c:0c:0d:64:fb:81:31:98"
      cert_thumbprint     = "F44635472A588E55C1776DFEB4A3E36D6E2A5E2B"
      cert_valid_from     = "2024-10-18"
      cert_valid_to       = "2025-10-19"

      country             = "CN"
      state               = "Sichuan"
      locality            = "Chengdu"
      email               = "???"
      rdn_serial_number   = "91510100MA6B62U07Y"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "35:4a:e1:38:1c:0c:0d:64:fb:81:31:98"
      )
}
