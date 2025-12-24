import "pe"

rule MAL_Compromised_Cert_MacSync_Apple_743AC6B4C08DDA28 {
   meta:
      description         = "Detects MacSync with compromised cert (Apple)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-18"
      version             = "1.0"

      hash                = "b591bfbab57cc69ce985fbc426002ef00826605257de0547f20ebcfecc3724c2"
      malware             = "MacSync"
      malware_type        = "Infostealer"
      malware_notes       = "Recently observed infostealer: https://www.jamf.com/blog/macsync-stealer-evolution-code-signed-swift-malware-analysis/"

      signer              = "FERDI AKYEL"
      cert_issuer_short   = "Apple"
      cert_issuer         = "Apple Inc."
      cert_serial         = "74:3a:c6:b4:c0:8d:da:28"
      cert_thumbprint     = "5F6CB4AB29EDD0FB82587491B2E874AE26F677AB"
      cert_valid_from     = "2025-12-18"
      cert_valid_to       = "2027-02-01"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Apple Inc." and
         sig.serial == "74:3a:c6:b4:c0:8d:da:28"
      )
}
