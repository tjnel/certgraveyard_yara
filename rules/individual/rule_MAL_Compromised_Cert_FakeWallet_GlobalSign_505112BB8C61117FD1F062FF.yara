import "pe"

rule MAL_Compromised_Cert_FakeWallet_GlobalSign_505112BB8C61117FD1F062FF {
   meta:
      description         = "Detects FakeWallet with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-29"
      version             = "1.0"

      hash                = "b531ee0e453c6a514daa09a4e7d6e8fae8f433269afba59035d84e68a5ff42a2"
      malware             = "FakeWallet"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "PIXEL PLAY PRIVATE LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "50:51:12:bb:8c:61:11:7f:d1:f0:62:ff"
      cert_thumbprint     = "6476E7D6F7FA90F5A4053A8A9280A90EFCFCAC97"
      cert_valid_from     = "2025-12-29"
      cert_valid_to       = "2026-12-30"

      country             = "IN"
      state               = "Delhi"
      locality            = "New Delhi"
      email               = "???"
      rdn_serial_number   = "U72300DL2015PTC276600"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "50:51:12:bb:8c:61:11:7f:d1:f0:62:ff"
      )
}
