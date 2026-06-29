import "pe"

rule MAL_Compromised_Cert_T_21_GlobalSign_7A9A0EDE87BF4EBE884BCCD6 {
   meta:
      description         = "Detects T-21 with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-08"
      version             = "1.0"

      hash                = "e79f02e9176a3cdd4696bb88040549bfb16471ee486f717a7f8291cf21c0d59d"
      malware             = "T-21"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Ali-Nur LTD LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "7a:9a:0e:de:87:bf:4e:be:88:4b:cc:d6"
      cert_thumbprint     = "A903614F3A45D67FB7F53CE7F3E7969F07D3B9D8"
      cert_valid_from     = "2026-04-08"
      cert_valid_to       = "2027-04-04"

      country             = "KG"
      state               = "Osh"
      locality            = "Osh"
      email               = "Alinurltd@proton.me"
      rdn_serial_number   = "177213-3310-OOO"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "7a:9a:0e:de:87:bf:4e:be:88:4b:cc:d6"
      )
}
