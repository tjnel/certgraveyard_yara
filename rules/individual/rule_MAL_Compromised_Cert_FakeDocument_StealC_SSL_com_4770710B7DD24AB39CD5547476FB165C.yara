import "pe"

rule MAL_Compromised_Cert_FakeDocument_StealC_SSL_com_4770710B7DD24AB39CD5547476FB165C {
   meta:
      description         = "Detects FakeDocument, StealC with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-14"
      version             = "1.0"

      hash                = "63e5c46d544ed7193f4e185037be2cb893a539dc53f52396138111006f9bdb30"
      malware             = "FakeDocument, StealC"
      malware_type        = "Unknown"
      malware_notes       = "Payload reaches out to http://192.109.200.164/to/invoice20026556576888.exe to download second stage, loads image of someone's passport as a decoy. The second stage was 378cbfe69f13ddeca3e599b5273a545a683c7537ec9ec6011a0cc7cb3b13c0b7."

      signer              = "ENGINEERING AND TECHNICAL PROCUREMENT SERVICES LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "47:70:71:0b:7d:d2:4a:b3:9c:d5:54:74:76:fb:16:5c"
      cert_thumbprint     = "FFD6CCC7D0D340A6F1296CB94F461BFB6EEB5E4E"
      cert_valid_from     = "2026-04-14"
      cert_valid_to       = "2027-04-14"

      country             = "GB"
      state               = "???"
      locality            = "Benfleet"
      email               = "???"
      rdn_serial_number   = "07993399"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "47:70:71:0b:7d:d2:4a:b3:9c:d5:54:74:76:fb:16:5c"
      )
}
