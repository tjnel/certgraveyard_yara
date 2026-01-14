import "pe"

rule MAL_Compromised_Cert_ZhongStealer_SSL_com_6FC27F0BBACFAA99807405016341540A {
   meta:
      description         = "Detects ZhongStealer with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-20"
      version             = "1.0"

      hash                = "6650052939aa7e4fe49c9d1aff74319c46506efe341f6d9e6d9900cdb7e40c91"
      malware             = "ZhongStealer"
      malware_type        = "Infostealer"
      malware_notes       = "An infostealer used by a Chinese cybercrime group tracked as Golden eye dog. Pulls second stage from legitimate CDN."

      signer              = "Schäfer Informatik GmbH"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "6f:c2:7f:0b:ba:cf:aa:99:80:74:05:01:63:41:54:0a"
      cert_thumbprint     = "37F65607307BA60C409086FFDA3070A39A470905"
      cert_valid_from     = "2024-12-20"
      cert_valid_to       = "2027-12-20"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "6f:c2:7f:0b:ba:cf:aa:99:80:74:05:01:63:41:54:0a"
      )
}
