import "pe"

rule MAL_Compromised_Cert_Forever_Botnet_BR_01_Sectigo_16878C94E69665A0CF308DDB789EADDC {
   meta:
      description         = "Detects Forever Botnet,BR-01 with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-12"
      version             = "1.0"

      hash                = "bfc632e5040adbec76ae73c182be3910fc314bde743ca2a69c2a0c8e95c0fdc2"
      malware             = "Forever Botnet,BR-01"
      malware_type        = "Infostealer"
      malware_notes       = ""

      signer              = "Jinan Baolian Deng Network Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "16:87:8c:94:e6:96:65:a0:cf:30:8d:db:78:9e:ad:dc"
      cert_thumbprint     = "D11104E441C420125081180A718D1763DFF4D265"
      cert_valid_from     = "2026-03-12"
      cert_valid_to       = "2027-03-12"

      country             = "CN"
      state               = "Shandong Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91370100069009206W"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "16:87:8c:94:e6:96:65:a0:cf:30:8d:db:78:9e:ad:dc"
      )
}
