import "pe"

rule MAL_Compromised_Cert_RUS_53_GlobalSign_5201CD9AFB0D56EC78F86942 {
   meta:
      description         = "Detects RUS-53 with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-24"
      version             = "1.0"

      hash                = "df9fefadf7012452f597602f84a31f6e40637004260c1457f819ce1ceb89b7d2"
      malware             = "RUS-53"
      malware_type        = "Loader"
      malware_notes       = ""

      signer              = "厦门鑫美泰网络科技有限公司"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "52:01:cd:9a:fb:0d:56:ec:78:f8:69:42"
      cert_thumbprint     = "6DB27770FBDC3F77439BBDCAE27E8646B545549C"
      cert_valid_from     = "2026-04-24"
      cert_valid_to       = "2027-04-25"

      country             = "CN"
      state               = "福建"
      locality            = "厦门"
      email               = "???"
      rdn_serial_number   = "91350203093262877K"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "52:01:cd:9a:fb:0d:56:ec:78:f8:69:42"
      )
}
