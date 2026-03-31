import "pe"

rule MAL_Compromised_Cert_RomCom_GlobalSign_02EB8FA2C506DAAF6D4CC641 {
   meta:
      description         = "Detects RomCom with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-20"
      version             = "1.0"

      hash                = "1d03b2544e313266cf43f3744391cc0a9f91f30be8c1bc47f67c6a7d6118165e"
      malware             = "RomCom"
      malware_type        = "Initial access tool"
      malware_notes       = "Dropped from fake GoogleDrive."

      signer              = "INLINE SOFTWARE ANS"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "02:eb:8f:a2:c5:06:da:af:6d:4c:c6:41"
      cert_thumbprint     = "AF80872643182ADD9724708F7892F936993922C7"
      cert_valid_from     = "2026-02-20"
      cert_valid_to       = "2027-02-21"

      country             = "NO"
      state               = "Oslo"
      locality            = "Oslo"
      email               = "???"
      rdn_serial_number   = "990 163 898"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "02:eb:8f:a2:c5:06:da:af:6d:4c:c6:41"
      )
}
