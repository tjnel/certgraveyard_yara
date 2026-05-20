import "pe"

rule MAL_Compromised_Cert_VariantLoader_Microsoft_33000028B0809900E9D48C32E90000000028B0 {
   meta:
      description         = "Detects VariantLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-10"
      version             = "1.0"

      hash                = "56d8a5a33ed1e2be85637b05d07a0b0db04a8565fe7a2616a2c6e9061699dac8"
      malware             = "VariantLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "TECHNOLOGY APPRAISALS LIMITED"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:00:28:b0:80:99:00:e9:d4:8c:32:e9:00:00:00:00:28:b0"
      cert_thumbprint     = "B8BE6AF88727BC40766821E8F52DA0D794A28D92"
      cert_valid_from     = "2026-04-10"
      cert_valid_to       = "2026-04-13"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:00:28:b0:80:99:00:e9:d4:8c:32:e9:00:00:00:00:28:b0"
      )
}
