import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_9A11DB914EBBDADDD77712FDF1349D4A {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-21"
      version             = "1.0"

      hash                = "909ae699edfb6ee27f3317a8ac2b771f9fcf38f3e2160cd7efcc8fc91f6e6f18"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Essie Sound"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "9a:11:db:91:4e:bb:da:dd:d7:77:12:fd:f1:34:9d:4a"
      cert_thumbprint     = "5ee1c37b92c92e2b4f0d51cf3b2564af403953f8"
      cert_valid_from     = "2026-09-21"
      cert_valid_to       = "2027-09-21"

      country             = "NL"
      state               = "Friesland"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "9a:11:db:91:4e:bb:da:dd:d7:77:12:fd:f1:34:9d:4a"
      )
}
