import "pe"

rule MAL_Compromised_Cert_FakeDocument_GlobalSign_7CB161B58EB2E9DA1CD0A36D {
   meta:
      description         = "Detects FakeDocument with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-25"
      version             = "1.0"

      hash                = "75a5663b7b0b0100688f8004b99630041134c77c457bea2a3f9b55d68b4015d3"
      malware             = "FakeDocument"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Reviihuray Communication Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "7c:b1:61:b5:8e:b2:e9:da:1c:d0:a3:6d"
      cert_thumbprint     = "CB30938DE072D077D7ED3BCD018C482C7511AE28"
      cert_valid_from     = "2025-03-25"
      cert_valid_to       = "2026-03-26"

      country             = "---"
      state               = "---"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "7c:b1:61:b5:8e:b2:e9:da:1c:d0:a3:6d"
      )
}
