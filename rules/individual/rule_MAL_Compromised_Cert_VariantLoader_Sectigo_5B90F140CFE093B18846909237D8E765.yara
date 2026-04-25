import "pe"

rule MAL_Compromised_Cert_VariantLoader_Sectigo_5B90F140CFE093B18846909237D8E765 {
   meta:
      description         = "Detects VariantLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-15"
      version             = "1.0"

      hash                = "bacc2455cc75ea56bc072c7142c8f3fbc7bd52355bcfde15f7fae3b7d960b1fe"
      malware             = "VariantLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: 188.137.254.193"

      signer              = "G. Earl Family Investments LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "5b:90:f1:40:cf:e0:93:b1:88:46:90:92:37:d8:e7:65"
      cert_thumbprint     = "98C4DD03589FDE173C2590813C23305A9029E7A9"
      cert_valid_from     = "2026-04-15"
      cert_valid_to       = "2027-04-15"

      country             = "US"
      state               = "Arizona"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "L18847292"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "5b:90:f1:40:cf:e0:93:b1:88:46:90:92:37:d8:e7:65"
      )
}
