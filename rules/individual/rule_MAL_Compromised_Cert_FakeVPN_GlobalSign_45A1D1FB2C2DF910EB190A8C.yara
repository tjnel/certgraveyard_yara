import "pe"

rule MAL_Compromised_Cert_FakeVPN_GlobalSign_45A1D1FB2C2DF910EB190A8C {
   meta:
      description         = "Detects FakeVPN with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-01"
      version             = "1.0"

      hash                = "66963a9ddd424d96ba78b6158343529a4a95b2b33f19bdf55518f6000a6d5751"
      malware             = "FakeVPN"
      malware_type        = "Backdoor"
      malware_notes       = "VPN installer distributed via malvertising"

      signer              = "OOO Severnyj Proekt"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "45:a1:d1:fb:2c:2d:f9:10:eb:19:0a:8c"
      cert_thumbprint     = "FAC73D1D98ACDC30F284D3AD1A09B2D9C412FF86"
      cert_valid_from     = "2026-04-01"
      cert_valid_to       = "2027-04-02"

      country             = "RU"
      state               = "Sankt-Peterburg"
      locality            = "Sankt-Peterburg"
      email               = "???"
      rdn_serial_number   = "1147847027074"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "45:a1:d1:fb:2c:2d:f9:10:eb:19:0a:8c"
      )
}
