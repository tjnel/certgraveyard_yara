import "pe"

rule MAL_Compromised_Cert_Traffer_GlobalSign_1B282C1B3E5EF170CBF9993A {
   meta:
      description         = "Detects Traffer with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-10"
      version             = "1.0"

      hash                = "99252f6681b759839440d51a944732e6baaaa2d5ef959001dd578735ef2560fe"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "GANGWORKS SOFTWARE YAZILIM TEKNOLOJİ LİMİTED ŞİRKETİ"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "1b:28:2c:1b:3e:5e:f1:70:cb:f9:99:3a"
      cert_thumbprint     = "3B061BCB9446C8B3068E9EAEE1A9725128EEF61E"
      cert_valid_from     = "2026-03-10"
      cert_valid_to       = "2027-03-11"

      country             = "TR"
      state               = "Istanbul"
      locality            = "Istanbul"
      email               = "???"
      rdn_serial_number   = "1087834"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "1b:28:2c:1b:3e:5e:f1:70:cb:f9:99:3a"
      )
}
