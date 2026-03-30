import "pe"

rule MAL_Compromised_Cert_EvilAI_Sectigo_0CF28ED37CB518C20C6EFCD550B0629B {
   meta:
      description         = "Detects EvilAI with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-16"
      version             = "1.0"

      hash                = "b34ad2bcea2f7e3459975747fa3e44fe958cad413bc5e45768bcbf86cf505fa2"
      malware             = "EvilAI"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Eos Mist LTD"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "0c:f2:8e:d3:7c:b5:18:c2:0c:6e:fc:d5:50:b0:62:9b"
      cert_thumbprint     = "6A9A8A2AF4D5006D4F639C2CDF6AEF7A64A46211"
      cert_valid_from     = "2026-02-16"
      cert_valid_to       = "2027-02-16"

      country             = "IL"
      state               = "Central"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "516234788"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "0c:f2:8e:d3:7c:b5:18:c2:0c:6e:fc:d5:50:b0:62:9b"
      )
}
