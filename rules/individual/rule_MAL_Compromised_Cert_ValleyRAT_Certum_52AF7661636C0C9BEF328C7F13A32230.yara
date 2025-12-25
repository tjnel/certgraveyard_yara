import "pe"

rule MAL_Compromised_Cert_ValleyRAT_Certum_52AF7661636C0C9BEF328C7F13A32230 {
   meta:
      description         = "Detects ValleyRAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-23"
      version             = "1.0"

      hash                = "84363809a16939c41a6766373a033c9ddb257c719b9ca59abe79e68dcfe80ae6"
      malware             = "ValleyRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This same signer name was used to sign ZhongStealer. More about ValleyRAT can be learned here: https://research.checkpoint.com/2025/cracking-valleyrat-from-builder-secrets-to-kernel-rootkits/"

      signer              = "RichQuest Network Technology Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "52:af:76:61:63:6c:0c:9b:ef:32:8c:7f:13:a3:22:30"
      cert_thumbprint     = "7DC762F855ED9E7A6B2FFB881CA680F004BEA306"
      cert_valid_from     = "2025-12-23"
      cert_valid_to       = "2026-12-23"

      country             = "CN"
      state               = "吉林省"
      locality            = "松原市"
      email               = "???"
      rdn_serial_number   = "91220702MABPBBD61L"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "52:af:76:61:63:6c:0c:9b:ef:32:8c:7f:13:a3:22:30"
      )
}
