import "pe"

rule MAL_Compromised_Cert_RUS_53_GlobalSign_287C387257A3BFA89A473C33 {
   meta:
      description         = "Detects RUS-53 with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-06"
      version             = "1.0"

      hash                = "163cf00168d6fd28366db6c88a1216f95b10b8bb71359d161b542a67c40bffc0"
      malware             = "RUS-53"
      malware_type        = "Loader"
      malware_notes       = ""

      signer              = "PHOTON architect design lab Limited Liability Company"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "28:7c:38:72:57:a3:bf:a8:9a:47:3c:33"
      cert_thumbprint     = "45B5F071148C8D4439E94A4ED3875C128DD46809"
      cert_valid_from     = "2026-04-06"
      cert_valid_to       = "2027-04-07"

      country             = "KG"
      state               = "Bishkek"
      locality            = "Bishkek"
      email               = "info@softdlp.com"
      rdn_serial_number   = "125615-3301-OOO"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "28:7c:38:72:57:a3:bf:a8:9a:47:3c:33"
      )
}
