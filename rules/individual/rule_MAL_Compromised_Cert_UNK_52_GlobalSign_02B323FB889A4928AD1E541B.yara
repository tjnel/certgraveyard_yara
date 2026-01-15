import "pe"

rule MAL_Compromised_Cert_UNK_52_GlobalSign_02B323FB889A4928AD1E541B {
   meta:
      description         = "Detects UNK-52 with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-03"
      version             = "1.0"

      hash                = "164421af114cb376d86e8c28d1b3749a3dbfa12328e928c22735930ff200aa28"
      malware             = "UNK-52"
      malware_type        = "Loader"
      malware_notes       = "A simple loader that uses python to execute a base64 encoded string and pull down a remote payload."

      signer              = "Montazhstroyservis  LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "02:b3:23:fb:88:9a:49:28:ad:1e:54:1b"
      cert_thumbprint     = "9F740FCC86F3D2057F510AE71113A8F907D2997D"
      cert_valid_from     = "2025-12-03"
      cert_valid_to       = "2026-12-04"

      country             = "RU"
      state               = "Saint Petersburg"
      locality            = "Saint Petersburg"
      email               = "???"
      rdn_serial_number   = "1187847320682"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "02:b3:23:fb:88:9a:49:28:ad:1e:54:1b"
      )
}
