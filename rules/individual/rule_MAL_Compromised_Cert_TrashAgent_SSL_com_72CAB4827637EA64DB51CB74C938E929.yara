import "pe"

rule MAL_Compromised_Cert_TrashAgent_SSL_com_72CAB4827637EA64DB51CB74C938E929 {
   meta:
      description         = "Detects TrashAgent with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-15"
      version             = "1.0"

      hash                = "a6fa63bc40edbed997c5dc6cd3be7104f99e2f5b76c7248c94b5e3e508b51174"
      malware             = "TrashAgent"
      malware_type        = "Initial access tool"
      malware_notes       = "The malware checks for enterprise apps and doesn't run unless they are present. The malware is frequently disguised as a PDF viewer and presents a fake error."

      signer              = "AudioFreq LLC"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "72:ca:b4:82:76:37:ea:64:db:51:cb:74:c9:38:e9:29"
      cert_thumbprint     = "1030F26D8811CC1BAB9F031A9B71D0E4DAD36FF8"
      cert_valid_from     = "2025-12-15"
      cert_valid_to       = "2026-12-15"

      country             = "US"
      state               = "Virginia"
      locality            = "Crozier"
      email               = "???"
      rdn_serial_number   = "11643998"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "72:ca:b4:82:76:37:ea:64:db:51:cb:74:c9:38:e9:29"
      )
}
