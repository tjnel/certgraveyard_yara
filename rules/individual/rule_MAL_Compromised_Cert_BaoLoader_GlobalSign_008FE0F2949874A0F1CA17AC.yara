import "pe"

rule MAL_Compromised_Cert_BaoLoader_GlobalSign_008FE0F2949874A0F1CA17AC {
   meta:
      description         = "Detects BaoLoader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-18"
      version             = "1.0"

      hash                = "099c77409d23507d65ee7783575c77c4eeee86cd35b9338ac6fcdfef894ad472"
      malware             = "BaoLoader"
      malware_type        = "Trojan"
      malware_notes       = ""

      signer              = "INCREDIBLE MEDIA INC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "00:8f:e0:f2:94:98:74:a0:f1:ca:17:ac"
      cert_thumbprint     = "5F64004455D6A8844A46C780C41E32CFC024380D"
      cert_valid_from     = "2024-04-18"
      cert_valid_to       = "2027-04-19"

      country             = "PA"
      state               = "Panamá"
      locality            = "Ciudad de Panamá"
      email               = "???"
      rdn_serial_number   = "155722937"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "00:8f:e0:f2:94:98:74:a0:f1:ca:17:ac"
      )
}
