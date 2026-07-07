import "pe"

rule MAL_Compromised_Cert_Golden_Gh0st_Loader_Sectigo_191E24F6C98E31D04F876A2E26E0CC71 {
   meta:
      description         = "Detects Golden Gh0st Loader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-21"
      version             = "1.0"

      hash                = "1a80f721ab125b88e5baf77dd2bf01be92ff5299665356621b21306a71c86672"
      malware             = "Golden Gh0st Loader"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Meizhou Fisherman Network Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "19:1e:24:f6:c9:8e:31:d0:4f:87:6a:2e:26:e0:cc:71"
      cert_thumbprint     = "90AB62209A3C3CDF63229669BBF1EE3546C7D34B"
      cert_valid_from     = "2025-05-21"
      cert_valid_to       = "2026-05-21"

      country             = "CN"
      state               = "Guangdong Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "19:1e:24:f6:c9:8e:31:d0:4f:87:6a:2e:26:e0:cc:71"
      )
}
